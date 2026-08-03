import { type ReactNode } from "react";
import { Navigate } from "react-router-dom";
import { useAuth } from "../contexts/AuthContext";

interface RoleGuardProps {
  allowedRoles: ("Admin" | "Manager" | "Analyst" | "ReadOnly")[];
  children: ReactNode;
}

export default function RoleGuard({ allowedRoles, children }: RoleGuardProps) {
  const { user } = useAuth();
  const userRole = (user?.role?.name || "ReadOnly") as "Admin" | "Manager" | "Analyst" | "ReadOnly";

  if (!allowedRoles.includes(userRole)) {
    return <Navigate to="/403" replace />;
  }

  return <>{children}</>;
}
