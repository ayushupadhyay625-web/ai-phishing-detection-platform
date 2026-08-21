import {
  BarChart3,
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

import { useState } from "react";

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


const Layout = () => {
  const {
    user,
    logout,
  } = useAuth();

  const [sidebarOpen, setSidebarOpen] =
    useState(false);


  const closeSidebar = () => {
    setSidebarOpen(false);
  };


  return (
    <div className="application-layout">
      <button
        type="button"
        className="mobile-menu-button"
        onClick={() => setSidebarOpen(true)}
        aria-label="Open navigation"
      >
        <Menu size={22} />
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
          <div className="auth-brand">
            <div className="brand-icon">
              <ShieldCheck size={24} />
            </div>

            <div>
              <strong>PHISHGUARD AI</strong>
              <span>SECURITY OPERATIONS</span>
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


        <nav className="sidebar-navigation">
          <p>NAVIGATION</p>

          {navigationItems.map((item) => {
            const Icon = item.icon;

            return (
              <NavLink
                key={item.path}
                to={item.path}
                onClick={closeSidebar}
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


        <div className="sidebar-user">
          <div className="user-avatar">
            {user?.name
              ?.charAt(0)
              .toUpperCase()}
          </div>

          <div className="user-details">
            <strong>{user?.name}</strong>
            <span>
              {user?.role
                ?.replace("_", " ")}
            </span>
          </div>

          <button
            type="button"
            className="logout-button"
            onClick={logout}
            aria-label="Sign out"
          >
            <LogOut size={18} />
          </button>
        </div>
      </aside>


      <div className="application-content">
        <header className="top-header">
          <div>
            <span className="live-status">
              <i />
              Protection active
            </span>
          </div>

          <div className="header-identity">
            <span>
              {user?.role
                ?.replace("_", " ")}
            </span>

            <strong>{user?.name}</strong>
          </div>
        </header>


        <div className="page-content">
          <Outlet />
        </div>
      </div>
    </div>
  );
};


export default Layout;