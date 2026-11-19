import { NavLink, Navigate, Route, Routes } from 'react-router-dom';
import { useAuth } from './auth.jsx';
import AlertDetail from './pages/AlertDetail.jsx';
import Alerts from './pages/Alerts.jsx';
import Login from './pages/Login.jsx';
import Model from './pages/Model.jsx';
import Overview from './pages/Overview.jsx';

export default function App() {
  const { user, ready, logout } = useAuth();
  if (!ready) return <p className="center muted">Loading...</p>;
  if (!user) return <Login />;
  return (
    <>
      <header className="top">
        <div className="brand"><span aria-hidden="true">◉</span> ThreatLens</div>
        <nav aria-label="Main">
          <NavLink to="/" end>Overview</NavLink>
          <NavLink to="/alerts">Alerts</NavLink>
          <NavLink to="/model">Model</NavLink>
        </nav>
        <div className="who">
          <span>{user.username} <small className="role">{user.role}</small></span>
          <button type="button" className="btn" onClick={logout}>Sign out</button>
        </div>
      </header>
      <main>
        <Routes>
          <Route path="/" element={<Overview />} />
          <Route path="/alerts" element={<Alerts />} />
          <Route path="/alerts/:id" element={<AlertDetail />} />
          <Route path="/model" element={<Model />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
    </>
  );
}
