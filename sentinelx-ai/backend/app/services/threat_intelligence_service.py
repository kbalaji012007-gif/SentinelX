"""
SentinelX AI – Threat Intelligence Service Layer
Business logic for threat feeds, IOC feeds, reputation, MITRE ATT&CK, external provider lookups, and caching.
"""

import asyncio
from uuid import UUID
from datetime import datetime, timezone
from typing import Sequence, Dict, Any, List
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import HTTPException, status

from app.repositories.threat_intelligence_repo import (
    ThreatFeedRepository,
    IOCRepository,
    MitreRepository,
    ThreatCacheRepository,
)
from app.schemas.threat_intelligence_schema import (
    ThreatFeedCreate,
    ThreatFeedUpdate,
    ThreatFeedListResponse,
    ThreatFeedResponse,
    IOCFeedCreate,
    IOCFeedUpdate,
    IOCFeedListResponse,
    IOCFeedResponse,
    IOCReputationResponse,
    MitreTechniqueCreate,
    MitreTechniqueListResponse,
    MitreTechniqueResponse,
    ThreatIntelStatsResponse,
    IOCLookupResponse,
    ProviderResultItem,
    ProviderStatusItem,
    ProviderStatusListResponse,
    CacheStatsResponse,
)
from app.services.threat_intelligence.providers import (
    VirusTotalProvider,
    AbuseIPDBProvider,
    ShodanProvider,
    GeminiThreatProvider,
    list_provider_statuses,
)


class ThreatIntelService:
    """Service orchestrating Threat Intelligence database operations and external provider lookups."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.feed_repo = ThreatFeedRepository(session)
        self.ioc_repo = IOCRepository(session)
        self.mitre_repo = MitreRepository(session)
        self.cache_repo = ThreatCacheRepository(session)

        # Provider clients
        self.vt_provider = VirusTotalProvider()
        self.abuse_provider = AbuseIPDBProvider()
        self.shodan_provider = ShodanProvider()
        self.gemini_provider = GeminiThreatProvider()

    # ── External Threat Intelligence Provider Orchestration ─────────────────

    async def lookup_ip(self, ip: str, force_refresh: bool = False) -> IOCLookupResponse:
        """Lookup IP reputation across VirusTotal, AbuseIPDB, Shodan, and Gemini AI."""
        return await self.enrich_ioc(ioc_type="IP", value=ip, force_refresh=force_refresh)

    async def lookup_domain(self, domain: str, force_refresh: bool = False) -> IOCLookupResponse:
        """Lookup Domain reputation across VirusTotal and Gemini AI."""
        return await self.enrich_ioc(ioc_type="Domain", value=domain, force_refresh=force_refresh)

    async def lookup_url(self, url: str, force_refresh: bool = False) -> IOCLookupResponse:
        """Lookup URL reputation across VirusTotal and Gemini AI."""
        return await self.enrich_ioc(ioc_type="URL", value=url, force_refresh=force_refresh)

    async def lookup_hash(self, file_hash: str, force_refresh: bool = False) -> IOCLookupResponse:
        """Lookup File Hash reputation across VirusTotal and Gemini AI."""
        return await self.enrich_ioc(ioc_type="FileHash-SHA256", value=file_hash, force_refresh=force_refresh)

    async def lookup_host(self, host: str, force_refresh: bool = False) -> IOCLookupResponse:
        """Lookup Host details across Shodan, VirusTotal, and Gemini AI."""
        return await self.enrich_ioc(ioc_type="Host", value=host, force_refresh=force_refresh)

    async def lookup_ioc(self, ioc_type: str, value: str, force_refresh: bool = False) -> IOCLookupResponse:
        """Generic IOC lookup dispatcher."""
        return await self.enrich_ioc(ioc_type=ioc_type, value=value, force_refresh=force_refresh)

    async def enrich_ioc(self, ioc_type: str, value: str, force_refresh: bool = False) -> IOCLookupResponse:
        """
        Enrich IOC by querying external providers with cache-first strategy.
        If cache hit & valid: returns cached analysis.
        Otherwise: executes provider queries concurrently, synthesizes scores, caches result, and upserts IOC reputation.
        """
        clean_val = value.strip()
        query_key = f"ioc:{ioc_type.lower()}:{clean_val.lower()}"

        # 1. Cache-First Strategy
        if not force_refresh:
            cached = await self.cache_repo.get_valid_cache(query_key)
            if cached and cached.response_data:
                cached_data = cached.response_data
                cached_data["cache_hit"] = True
                cached_data["cached_at"] = cached.created_at.isoformat() if cached.created_at else None
                cached_data["expires_at"] = cached.expires_at.isoformat() if cached.expires_at else None
                return IOCLookupResponse.model_validate(cached_data)

        # 2. Query External Providers Concurrently
        vt_task = self._query_vt(ioc_type, clean_val)
        abuse_task = self._query_abuse(ioc_type, clean_val)
        shodan_task = self._query_shodan(ioc_type, clean_val)

        vt_res, abuse_res, shodan_res = await asyncio.gather(
            vt_task, abuse_task, shodan_task, return_exceptions=True
        )

        providers_raw = {
            "VirusTotal": self._handle_provider_exception("VirusTotal", vt_res),
            "AbuseIPDB": self._handle_provider_exception("AbuseIPDB", abuse_res),
            "Shodan": self._handle_provider_exception("Shodan", shodan_res),
        }

        # 3. Query Gemini AI for IOC Explanation & Threat Summary
        gemini_res = await self.generate_ai_summary(ioc_type, clean_val, context=providers_raw)
        providers_raw["Google Gemini AI"] = gemini_res

        # 4. Compare Provider Results & Aggregate Verdict
        comparison = self.compare_provider_results(ioc_type, clean_val, providers_raw)

        # Build ProviderResultItem objects
        provider_items: Dict[str, ProviderResultItem] = {}
        for p_name, p_data in providers_raw.items():
            provider_items[p_name] = ProviderResultItem(
                provider=p_name,
                status=p_data.get("status", "unavailable"),
                reason=p_data.get("reason"),
                data=p_data.get("data"),
            )

        # 5. Extract MITRE ATT&CK and AI Summary data
        gemini_data = gemini_res.get("data") if gemini_res.get("status") == "available" else None
        mitre_mapping = []
        if gemini_data and isinstance(gemini_data, dict):
            mitre_mapping = gemini_data.get("mitre_attack", [])

        # 6. Timeline items
        now_dt = datetime.now(timezone.utc)
        timeline = [
            {"event": "First Discovered / Analysis Requested", "timestamp": now_dt.isoformat()},
            {"event": "Provider Inquiries Dispatched", "timestamp": now_dt.isoformat()},
            {"event": f"Aggregated Verdict Evaluated: {comparison['verdict']}", "timestamp": now_dt.isoformat()},
        ]

        response_dict = {
            "ioc_value": clean_val,
            "ioc_type": ioc_type,
            "verdict": comparison["verdict"],
            "threat_score": comparison["threat_score"],
            "confidence": comparison["confidence"],
            "reputation": comparison["reputation"],
            "cache_hit": False,
            "cached_at": now_dt.isoformat(),
            "expires_at": datetime.fromtimestamp(now_dt.timestamp() + 3600, tz=timezone.utc).isoformat(),
            "providers": provider_items,
            "gemini_summary": gemini_data,
            "mitre_mapping": mitre_mapping,
            "timeline": timeline,
        }

        # 7. Cache Lookup & Persist Reputation
        await self.cache_lookup(
            query_key=query_key,
            query_type=ioc_type,
            data=response_dict,
            ttl=3600,
        )

        await self.ioc_repo.upsert_reputation(
            ioc_value=clean_val,
            ioc_type=ioc_type,
            reputation_score=comparison["threat_score"],
            verdict=comparison["verdict"],
            threat_category=comparison["verdict"],
            details=response_dict,
        )

        return IOCLookupResponse.model_validate(response_dict)

    async def generate_ai_summary(
        self, ioc_type: str, value: str, context: Dict[str, Any] | None = None
    ) -> Dict[str, Any]:
        """Call GeminiThreatProvider to synthesize AI threat summary & explanation."""
        return await self.gemini_provider.generate_ai_analysis(ioc_type, value, context)

    def compare_provider_results(
        self, ioc_type: str, value: str, results: Dict[str, Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Synthesize provider outputs to determine composite threat score, confidence, and verdict.
        Only uses available providers. Returns unavailable status metadata if all providers unavailable.
        """
        available_scores: List[int] = []
        verdicts: List[str] = []

        for p_name, res in results.items():
            if res.get("status") == "available" and res.get("data"):
                p_data = res["data"]
                if "threat_score" in p_data and isinstance(p_data["threat_score"], (int, float)):
                    available_scores.append(int(p_data["threat_score"]))
                if "verdict" in p_data and p_data["verdict"]:
                    verdicts.append(p_data["verdict"])

        if not available_scores:
            return {
                "threat_score": 0,
                "confidence": 0,
                "verdict": "Unknown",
                "reputation": "No providers available or configured",
            }

        max_score = max(available_scores)
        avg_score = int(sum(available_scores) / len(available_scores))
        composite_score = min(100, int((max_score * 0.7) + (avg_score * 0.3)))

        verdict = "Harmless"
        if "Malicious" in verdicts or composite_score >= 70:
            verdict = "Malicious"
        elif "Suspicious" in verdicts or composite_score >= 30:
            verdict = "Suspicious"

        confidence = min(100, 60 + (len(available_scores) * 10))
        reputation = f"{verdict} ({composite_score}/100 based on {len(available_scores)} active provider(s))"

        return {
            "threat_score": composite_score,
            "confidence": confidence,
            "verdict": verdict,
            "reputation": reputation,
        }

    async def cache_lookup(
        self, query_key: str, query_type: str, data: Dict[str, Any], ttl: int = 3600
    ) -> None:
        """Save query result to Threat Intelligence Cache in database."""
        # Convert Pydantic models in data dict to JSON serializable objects
        json_data = json_safe_dict(data)
        await self.cache_repo.set_cache(
            query_key=query_key,
            query_type=query_type,
            response_data=json_data,
            ttl_seconds=ttl,
        )

    # ── Provider Status & Telemetry ──────────────────────────────────────────

    async def get_provider_statuses(self) -> ProviderStatusListResponse:
        """Return status and configuration readiness for all external providers."""
        raw_list = list_provider_statuses()
        items = [ProviderStatusItem.model_validate(p) for p in raw_list]
        return ProviderStatusListResponse(providers=items)

    async def get_cache_stats(self) -> CacheStatsResponse:
        """Fetch threat intelligence cache statistics."""
        total = await self.cache_repo.count_total_cache()
        active = await self.cache_repo.count_valid_cache()
        hit_ratio = round((active / total) * 100, 1) if total > 0 else 0.0

        recents = await self.cache_repo.list_recent_cache_entries(limit=10)
        recent_keys = [c.query_key for c in recents]

        return CacheStatsResponse(
            total_cached=total,
            active_cached=active,
            cache_hit_ratio=hit_ratio,
            recent_keys=recent_keys,
        )

    # ── Helper Query Methods ────────────────────────────────────────────────

    async def _query_vt(self, ioc_type: str, value: str) -> Dict[str, Any]:
        if ioc_type == "IP":
            return await self.vt_provider.lookup_ip(value)
        elif ioc_type == "Domain":
            return await self.vt_provider.lookup_domain(value)
        elif ioc_type == "URL":
            return await self.vt_provider.lookup_url(value)
        elif ioc_type in ("FileHash-MD5", "FileHash-SHA1", "FileHash-SHA256"):
            return await self.vt_provider.lookup_hash(value)
        elif ioc_type == "Host":
            return await self.vt_provider.lookup_host(value)
        return await self.vt_provider.lookup_ip(value)

    async def _query_abuse(self, ioc_type: str, value: str) -> Dict[str, Any]:
        if ioc_type in ("IP", "Host"):
            return await self.abuse_provider.lookup_ip(value)
        return self.abuse_provider.build_unavailable_response("AbuseIPDB only supports IP reputation lookups")

    async def _query_shodan(self, ioc_type: str, value: str) -> Dict[str, Any]:
        if ioc_type in ("IP", "Host"):
            return await self.shodan_provider.lookup_host(value)
        return self.shodan_provider.build_unavailable_response("Shodan direct host lookup requires an IP address")

    def _handle_provider_exception(self, provider_name: str, res: Any) -> Dict[str, Any]:
        if isinstance(res, Exception):
            return {
                "provider": provider_name,
                "status": "unavailable",
                "reason": f"Provider execution failed: {str(res)}",
                "data": None,
            }
        if isinstance(res, dict):
            return res
        return {
            "provider": provider_name,
            "status": "unavailable",
            "reason": "Unexpected provider return type",
            "data": None,
        }

    # ── Threat Feeds ──────────────────────────────────────────────────

    async def list_feeds(
        self,
        page: int = 1,
        page_size: int = 25,
        status_filter: str | None = None,
        feed_type: str | None = None,
    ) -> ThreatFeedListResponse:
        """Fetch paginated list of threat feeds."""
        skip = (page - 1) * page_size
        items = await self.feed_repo.list_feeds(
            skip=skip, limit=page_size, status=status_filter, feed_type=feed_type
        )
        total = await self.feed_repo.count_feeds(status=status_filter, feed_type=feed_type)

        return ThreatFeedListResponse(
            total=total,
            page=page,
            page_size=page_size,
            items=[ThreatFeedResponse.model_validate(item) for item in items],
        )

    async def create_feed(self, payload: ThreatFeedCreate) -> ThreatFeedResponse:
        """Register a new threat feed."""
        existing = await self.feed_repo.get_by_name(payload.feed_name)
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Threat feed with name '{payload.feed_name}' already exists",
            )
        feed = await self.feed_repo.create(payload.model_dump())
        return ThreatFeedResponse.model_validate(feed)

    # ── IOC Items ─────────────────────────────────────────────────────

    async def list_iocs(
        self,
        page: int = 1,
        page_size: int = 25,
        ioc_type: str | None = None,
        severity: str | None = None,
        feed_id: UUID | None = None,
        search: str | None = None,
    ) -> IOCFeedListResponse:
        """Fetch paginated list of IOC items."""
        skip = (page - 1) * page_size
        items = await self.ioc_repo.list_iocs(
            skip=skip,
            limit=page_size,
            ioc_type=ioc_type,
            severity=severity,
            feed_id=feed_id,
            search=search,
        )
        total = await self.ioc_repo.count_iocs(
            ioc_type=ioc_type, severity=severity, feed_id=feed_id, search=search
        )

        return IOCFeedListResponse(
            total=total,
            page=page,
            page_size=page_size,
            items=[IOCFeedResponse.model_validate(item) for item in items],
        )

    async def create_ioc(self, payload: IOCFeedCreate) -> IOCFeedResponse:
        """Add a new IOC item."""
        if payload.feed_id:
            feed = await self.feed_repo.get_by_id(payload.feed_id)
            if not feed:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Feed ID {payload.feed_id} not found",
                )

        ioc = await self.ioc_repo.create(payload.model_dump())

        if payload.feed_id:
            feed = await self.feed_repo.get_by_id(payload.feed_id)
            if feed:
                feed.total_indicators += 1

        return IOCFeedResponse.model_validate(ioc)

    # ── MITRE ATT&CK ──────────────────────────────────────────────────

    async def list_mitre_techniques(
        self,
        page: int = 1,
        page_size: int = 25,
        tactic: str | None = None,
        search: str | None = None,
    ) -> MitreTechniqueListResponse:
        """Fetch paginated list of MITRE ATT&CK techniques."""
        skip = (page - 1) * page_size
        items = await self.mitre_repo.list_techniques(
            skip=skip, limit=page_size, tactic=tactic, search=search
        )
        total = await self.mitre_repo.count_techniques(tactic=tactic, search=search)

        return MitreTechniqueListResponse(
            total=total,
            page=page,
            page_size=page_size,
            items=[MitreTechniqueResponse.model_validate(item) for item in items],
        )

    # ── Statistics ────────────────────────────────────────────────────

    async def get_statistics(self) -> ThreatIntelStatsResponse:
        """Compute Threat Intelligence overview statistics."""
        total_feeds = await self.feed_repo.count_feeds()
        active_feeds = await self.feed_repo.count_feeds(status="Active")
        total_iocs = await self.ioc_repo.count_iocs()

        iocs_by_severity = {}
        for sev in ["Critical", "High", "Medium", "Low", "Info"]:
            cnt = await self.ioc_repo.count_iocs(severity=sev)
            if cnt > 0:
                iocs_by_severity[sev] = cnt

        iocs_by_type = {}
        for t in ["IP", "Domain", "URL", "FileHash-MD5", "FileHash-SHA256", "Email"]:
            cnt = await self.ioc_repo.count_iocs(ioc_type=t)
            if cnt > 0:
                iocs_by_type[t] = cnt

        mitre_count = await self.mitre_repo.count_techniques()
        cache_stats = await self.get_cache_stats()

        return ThreatIntelStatsResponse(
            total_feeds=total_feeds,
            active_feeds=active_feeds,
            total_iocs=total_iocs,
            iocs_by_type=iocs_by_type,
            iocs_by_severity=iocs_by_severity,
            mitre_technique_count=mitre_count,
            cached_query_count=cache_stats.active_cached,
            cache_hit_ratio=cache_stats.cache_hit_ratio,
        )


def json_safe_dict(data: Any) -> Any:
    """Helper to convert Pydantic objects or non-serializable objects inside dicts."""
    if hasattr(data, "model_dump"):
        return json_safe_dict(data.model_dump())
    elif isinstance(data, dict):
        return {k: json_safe_dict(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [json_safe_dict(i) for i in data]
    elif isinstance(data, (datetime, UUID)):
        return str(data)
    return data
