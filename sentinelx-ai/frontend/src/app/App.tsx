import { Routes, Route } from "react-router-dom";
import Layout from "./Layout";
import ProtectedRoute from "../routes/ProtectedRoute";

import LoginPage from "../features/auth/LoginPage";
import SessionExpiredScreen from "../features/auth/SessionExpiredScreen";
import UnauthorizedPage from "../features/auth/UnauthorizedPage";

import DashboardPage from "../features/dashboard/DashboardPage";
import ThreatsPage from "../features/threats/ThreatsPage";
import IncidentsPage from "../features/incidents/IncidentsPage";
import AssetsPage from "../features/assets/AssetsPage";
import LogsPage from "../features/logs/LogsPage";
import IntelligencePage from "../features/intelligence/IntelligencePage";
import CorrelationPage from "../features/correlation/CorrelationPage";
import SOARPage from "../features/soar/SOARPage";
import VulnerabilitiesPage from "../features/vulnerabilities/VulnerabilitiesPage";
import AnalyticsPage from "../features/analytics/AnalyticsPage";
import ReportsPage from "../features/reports/ReportsPage";
import AiAssistantPage from "../features/ai-assistant/AiAssistantPage";
import AISOCPage from "../features/ai-soc/AISOCPage";
import UsersPage from "../features/users/UsersPage";
import SettingsPage from "../features/settings/SettingsPage";

function App() {
  return (
    <Routes>
      {/* Public Auth Routes */}
      <Route path="/login" element={<LoginPage />} />
      <Route path="/session-expired" element={<SessionExpiredScreen />} />
      <Route path="/403" element={<UnauthorizedPage />} />

      {/* Protected SOC Routes */}
      <Route
        element={
          <ProtectedRoute>
            <Layout />
          </ProtectedRoute>
        }
      >
        <Route index element={<DashboardPage />} />
        <Route path="threats" element={<ThreatsPage />} />
        <Route path="incidents" element={<IncidentsPage />} />
        <Route path="assets" element={<AssetsPage />} />
        <Route path="logs" element={<LogsPage />} />
        <Route path="intelligence" element={<IntelligencePage />} />
        <Route path="correlation" element={<CorrelationPage />} />
        <Route path="soar" element={<SOARPage />} />
        <Route path="vulnerabilities" element={<VulnerabilitiesPage />} />
        <Route path="analytics" element={<AnalyticsPage />} />
        <Route path="reports" element={<ReportsPage />} />
        <Route path="ai-assistant" element={<AiAssistantPage />} />
        <Route path="ai-soc" element={<AISOCPage />} />
        <Route path="users" element={<UsersPage />} />
        <Route path="settings" element={<SettingsPage />} />
      </Route>
    </Routes>
  );
}

export default App;
