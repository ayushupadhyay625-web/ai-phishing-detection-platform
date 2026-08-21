import {
  BarChart3,
  Bell,
  CalendarDays,
  ChevronLeft,
  ChevronRight,
  FileSearch,
  History,
  Link2,
  LogOut,
  MailWarning,
  Menu,
  ShieldCheck,
  X,
} from "lucide-react";

import {
  NavLink,
  Outlet,
} from "react-router-dom";

import { useMemo, useState } from "react";

import { useAuth } from "../../context/AuthContext";


const navigationItems = [
  {
    name: "Dashboard",
    path: "/dashboard",
    icon: BarChart3,
  },
  {
    name: "Email Scanner",
    path: "/scan/email",
    icon: MailWarning,
  },
  {
    name: "URL Scanner",
    path: "/scan/url",
    icon: Link2,
  },
  {
    name: "Scan History",
    path: "/history",
    icon: History,
  },
  {
    name: "Reports",
    path: "/reports",
    icon: FileSearch,
  },
];


const formatRole = (role = "") => {
  return role
    .replaceAll("_", " ")
    .replace(/\b\w/g, (letter) =>
      letter.toUpperCase()
    );
};


const Layout = () => {
  const {
    user,
    logout,
  } = useAuth();

  const [sidebarOpen, setSidebarOpen] =
    useState(false);

  const [sidebarCollapsed, setSidebarCollapsed] =
    useState(false);


  const currentDate = useMemo(() => {
    return new Intl.DateTimeFormat("en-US", {
      month: "short",
      day: "numeric",
      year: "numeric",
    }).format(new Date());
  }, []);


  const greeting = useMemo(() => {
    const hour = new Date().getHours();

    if (hour < 12) {
      return "Good morning";
    }

    if (hour < 17) {
      return "Good afternoon";
    }

    return "Good evening";
  }, []);


  const closeSidebar = () => {
    setSidebarOpen(false);
  };


  const userInitials = user?.name
    ? user.name
        .split(" ")
        .slice(0, 2)
        .map((part) => part.charAt(0))
        .join("")
        .toUpperCase()
    : "PG";


  return (
    <div
      className={
        sidebarCollapsed
          ? "application-layout sidebar-is-collapsed"
          : "application-layout"
      }
    >
      <button
        type="button"
        className="mobile-menu-button"
        onClick={() => setSidebarOpen(true)}
        aria-label="Open navigation"
      >
        <Menu size={21} />
      </button>


      {sidebarOpen && (
        <button
          type="button"
          className="sidebar-overlay"
          onClick={closeSidebar}
          aria-label="Close navigation"
        />
      )}


      <aside
        className={
          sidebarOpen
            ? "sidebar sidebar-open"
            : "sidebar"
        }
      >
        <div className="sidebar-header">
          <div className="auth-brand sidebar-brand">
            <div className="brand-icon">
              <ShieldCheck size={24} />
            </div>

            <div className="brand-copy">
              <strong>PHISHGUARD AI</strong>
              <span>AI-POWERED EMAIL SECURITY</span>
            </div>
          </div>

          <button
            type="button"
            className="sidebar-close"
            onClick={closeSidebar}
            aria-label="Close navigation"
          >
            <X size={20} />
          </button>
        </div>


        <button
          type="button"
          className="sidebar-collapse-button"
          onClick={() =>
            setSidebarCollapsed(
              (current) => !current
            )
          }
          aria-label={
            sidebarCollapsed
              ? "Expand navigation"
              : "Collapse navigation"
          }
        >
          {sidebarCollapsed
            ? <ChevronRight size={17} />
            : <ChevronLeft size={17} />}
        </button>


        <nav className="sidebar-navigation">
          <p>NAVIGATION</p>

          {navigationItems.map((item) => {
            const Icon = item.icon;

            return (
              <NavLink
                key={item.path}
                to={item.path}
                onClick={closeSidebar}
                title={
                  sidebarCollapsed
                    ? item.name
                    : undefined
                }
                className={({ isActive }) =>
                  isActive
                    ? "navigation-link active"
                    : "navigation-link"
                }
              >
                <Icon size={19} />

                <span>{item.name}</span>
              </NavLink>
            );
          })}
        </nav>


        <div className="sidebar-security-status">
          <div className="security-status-orb">
            <ShieldCheck size={19} />
          </div>

          <div>
            <strong>Engine protected</strong>
            <span>All systems operational</span>
          </div>

          <i />
        </div>


        <div className="sidebar-user">
          <div className="user-avatar">
            {userInitials}
          </div>

          <div className="user-details">
            <strong>{user?.name}</strong>

            <span>{formatRole(user?.role)}</span>
          </div>

          <button
            type="button"
            className="logout-button"
            onClick={logout}
            aria-label="Sign out"
            title="Sign out"
          >
            <LogOut size={18} />
          </button>
        </div>
      </aside>


      <div className="application-content">
        <header className="top-header">
          <div className="header-welcome">
            <span>
              {greeting},{" "}
              <strong>{user?.name}</strong>
            </span>

            <small>
              Here&apos;s your security overview
              for today.
            </small>
          </div>


          <div className="header-actions">
            <div className="header-date">
              <CalendarDays size={17} />
              <span>{currentDate}</span>
            </div>

            <div className="header-protection">
              <i />
              <span>Protection active</span>
            </div>

            <button
              type="button"
              className="notification-button"
              aria-label="Security notifications"
            >
              <Bell size={18} />
              <span>3</span>
            </button>
          </div>
        </header>


        <main className="page-content">
          <Outlet />
        </main>
      </div>
    </div>
  );
};


export default Layout;