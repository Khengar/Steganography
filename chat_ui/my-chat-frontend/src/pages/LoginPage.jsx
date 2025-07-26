import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
// React-Bootstrap Imports
import Container from 'react-bootstrap/Container';
import Form from 'react-bootstrap/Form';
import Button from 'react-bootstrap/Button';
import Card from 'react-bootstrap/Card';
import Alert from 'react-bootstrap/Alert';

import { loginUser } from '../api'; // Import your API helper

function LoginPage() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [message, setMessage] = useState('');
  const [messageVariant, setMessageVariant] = useState('success'); // 'success' | 'danger'

  const navigate = useNavigate();

  const handleLogin = async (e) => {
    e.preventDefault(); // Prevent default form submission
    setMessage(''); // Clear previous messages

    try {
      const { ok, data } = await loginUser(username, password);

      if (ok) {
        setMessage(`Welcome, ${data.username}.`);
        setMessageVariant('success');
        setTimeout(() => navigate('/dashboard'), 1500); // Redirect after short delay
      } else {
        setMessage(data.msg || 'Invalid credentials.');
        setMessageVariant('danger');
      }
    } catch (error) {
      setMessage('Could not connect to the API server.');
      setMessageVariant('danger');
      console.error('Login error:', error);
    }
  };

  return (
    <Container className="d-flex justify-content-center align-items-center" style={{ minHeight: '100vh' }}>
      <Card style={{ width: '400px' }} className="p-4 shadow">
        <Card.Title className="text-center mb-4"><h2>Login</h2></Card.Title>
        <Card.Body>
          {message && <Alert variant={messageVariant}>{message}</Alert>}
          <Form onSubmit={handleLogin}>
            <Form.Group className="mb-3" controlId="loginFormUsername">
              <Form.Label>Username</Form.Label>
              <Form.Control 
                type="text" 
                placeholder="Enter username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
              />
            </Form.Group>

            <Form.Group className="mb-3" controlId="loginFormPassword">
              <Form.Label>Password</Form.Label>
              <Form.Control 
                type="password" 
                placeholder="Enter password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </Form.Group>

            <Button variant="primary" type="submit" className="w-100 mt-3">
              Login
            </Button>
          </Form>
          <div className="text-center mt-3">
            Don't have an account? <Link to="/register">Register here</Link>
          </div>
        </Card.Body>
      </Card>
    </Container>
  );
}

export default LoginPage;