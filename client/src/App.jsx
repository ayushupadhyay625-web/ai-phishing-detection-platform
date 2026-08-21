import {
  Navigate,
  Route,
  Routes,
} from "react-router-dom";

import Layout from "./components/layout/Layout";
import Dashboard from "./pages/Dashboard";
import EmailScanner from "./pages/EmailScanner";
import Login from "./pages/Login";
import ProtectedRoute from "./routes/ProtectedRoute";
import URLScanner from "./pages/URLScanner";
import ScanHistory from "./pages/ScanHistory";
import Reports from "./pages/Reports";

const App = () => {
  return (
    <Routes>
      <Route
        path="/login"
        element={<Login />}
      />


      <Route
        element={
          <ProtectedRoute>
            <Layout />
          </ProtectedRoute>
        }
      >
        <Route
          path="/dashboard"
          element={<Dashboard />}
        />

        <Route
          path="/scan/email"
          element={<EmailScanner />}
        />
      </Route>
<Route
  path="/scan/url"
  element={<URLScanner />}
/>

<Route
  path="/history"
  element={<ScanHistory />}
/>

<Route
  path="/reports"
  element={<Reports />}
/>
      <Route
        path="/"
        element={
          <Navigate
            to="/dashboard"
            replace
          />
        }
      />

      <Route
        path="*"
        element={
          <Navigate
            to="/dashboard"
            replace
          />
        }
      />
    </Routes>
  );
};


export default App;