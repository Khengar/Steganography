import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import LoginPage from './pages/LoginPage';
import RegisterPage from './pages/RegisterPage';
import DashboardPage from './pages/DashboardPage';
import ChatPage from './pages/ChatPage';
import { Container } from 'react-bootstrap'; // Using React-Bootstrap Container

// Simple authentication check (for hackathon)
const isAuthenticated = () => {
  return localStorage.getItem('token') !== null;
};

// A private route component
const PrivateRoute = ({ children }) => {
  return isAuthenticated() ? children : <Navigate to="/login" />;
};

function App() {
  return (
    <Router>
      <Container className="p-4"> {/* Added padding using Bootstrap class */}
        <Routes>
          <Route path="/register" element={<RegisterPage />} />
          <Route path="/login" element={<LoginPage />} />
          
          {/* Protected Routes */}
          <Route 
            path="/dashboard" 
            element={
              <PrivateRoute>
                <DashboardPage />
              </PrivateRoute>
            } 
          />
          <Route 
            path="/chat/:userId" 
            element={
              <PrivateRoute>
                <ChatPage />
              </PrivateRoute>
            } 
          />
          
          {/* Redirect root to login or dashboard based on auth status */}
          <Route 
            path="/" 
            element={isAuthenticated() ? <Navigate to="/dashboard" /> : <Navigate to="/login" />} 
          />
        </Routes>
      </Container>
    </Router>
  );
}

export default App;