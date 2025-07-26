import React, { useState, useEffect } from 'react';
import { 
  Container, Row, Col, Card, Button, Form, ListGroup, Spinner, Alert 
} from 'react-bootstrap';
import { useNavigate } from 'react-router-dom';
import { 
  getFriends, 
  getPendingFriendRequests, 
  sendFriendRequest, 
  acceptFriendRequest, 
  searchUsers 
} from '../api'; 

function DashboardPage() {
  const navigate = useNavigate();
  const username = localStorage.getItem('username'); 
  const currentUserId = localStorage.getItem('user_id'); 

  const [friends, setFriends] = useState([]);
  const [pendingRequests, setPendingRequests] = useState([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [searchResults, setSearchResults] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchLoading, setSearchLoading] = useState(false);
  const [message, setMessage] = useState('');
  const [messageVariant, setMessageVariant] = useState('success'); 

  const showAlert = (msg, variant) => {
    setMessage(msg);
    setMessageVariant(variant);
    setTimeout(() => setMessage(''), 3000); // Hide after 3 seconds
  };

  // --- Fetch Dashboard Data ---
    const fetchDashboardData = async () => {
    setLoading(true);
    try {
      const friendsData = await getFriends(); // Call getFriends()
      const pendingData = await getPendingFriendRequests(); // Call getPendingFriendRequests()

      console.log("API response for friendsData:", friendsData); // <-- New Log
      console.log("API response for pendingData:", pendingData); // <-- New Log

      // Ensure data is always an array before setting state
      setFriends(Array.isArray(friendsData) ? friendsData : []);
      setPendingRequests(Array.isArray(pendingData) ? pendingData : []);

    } catch (error) {
      // If an error occurs, explicitly set to empty arrays to prevent .map() errors
      setFriends([]);
      setPendingRequests([]);
      // ... (existing error handling) ...
      console.error('Dashboard data fetch error:', error);
      // Optional: Redirect to login if token is invalid (already there)
      if (error.message && error.message.includes('Unauthorized')) {
        handleLogout();
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDashboardData();
  }, []); 

  // --- Search Users ---
  const handleSearchUsers = async (e) => {
    e.preventDefault();
    if (!searchQuery.trim()) {
      setSearchResults([]);
      return;
    }
    setSearchLoading(true);
    try {
      const results = await searchUsers(searchQuery);
      setSearchResults(results);
    } catch (error) {
      showAlert('Search failed.', 'danger');
      console.error('Search error:', error);
    } finally {
      setSearchLoading(false);
    }
  };

  // --- Send Friend Request ---
  const handleSendRequest = async (recipientUsername) => {
    try {
      const data = await sendFriendRequest(recipientUsername);
      if (data.msg === "Friend request sent") {
        showAlert(`Friend request sent to ${recipientUsername}.`, 'success');
        setSearchResults([]); 
        setSearchQuery('');
      } else {
        showAlert(data.msg || 'Failed to send request.', 'danger');
      }
    } catch (error) {
      showAlert('Could not connect to send request.', 'danger');
      console.error('Send request error:', error);
    }
  };

  // --- Accept Friend Request ---
  const handleAcceptRequest = async (requesterId, requesterUsername) => {
    try {
      const data = await acceptFriendRequest(requesterId);
      if (data.msg === "Friend request accepted") {
        showAlert(`You are now friends with ${requesterUsername}.`, 'success');
        fetchDashboardData(); // Refresh data
      } else {
        showAlert(data.msg || 'Failed to accept request.', 'danger');
      }
    } catch (error) {
      showAlert('Could not connect to accept request.', 'danger');
      console.error('Accept request error:', error);
    }
  };

  // --- Logout ---
  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user_id');
    localStorage.removeItem('username');
    navigate('/login');
  };

  // --- Navigate to Chat ---
  const handleGoToChat = (friendId, friendUsername) => {
    navigate(`/chat/${friendId}`, { state: { friendUsername: friendUsername } });
  };


  return (
    <Container className="my-5">
      <Card className="p-4 shadow">
        <Card.Body>
          <Row className="mb-4 align-items-center">
            <Col>
              <h2>Welcome, {username}!</h2>
            </Col>
            <Col className="text-end">
              <Button variant="danger" onClick={handleLogout}>
                Logout
              </Button>
            </Col>
          </Row>

          {message && <Alert variant={messageVariant}>{message}</Alert>}

          <hr className="my-4" />

          {/* Find New Friends Section */}
          <h4 className="mb-3">Find New Friends</h4>
          <Form onSubmit={handleSearchUsers} className="mb-4">
            <Row>
              <Col>
                <Form.Control 
                  type="text" 
                  placeholder="Search username"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                />
              </Col>
              <Col xs="auto">
                <Button variant="primary" type="submit" disabled={searchLoading}>
                  {searchLoading ? <Spinner animation="border" size="sm" /> : 'Search'}
                </Button>
              </Col>
            </Row>
          </Form>
          {searchResults.length > 0 && (
            <ListGroup className="mb-4">
              {searchResults.map((user) => (
                <ListGroup.Item key={user.id} className="d-flex justify-content-between align-items-center">
                  {user.username}
                  <Button variant="outline-primary" size="sm" onClick={() => handleSendRequest(user.username)}>
                    Send Request
                  </Button>
                </ListGroup.Item>
              ))}
            </ListGroup>
          )}
          {searchResults.length === 0 && searchQuery.length > 0 && !searchLoading && (
              <p className="text-muted">No users found.</p>
          )}

          <hr className="my-4" />

          {/* Pending Friend Requests Section */}
          <h4 className="mb-3">Pending Friend Requests</h4>
          {loading ? (
            <div className="text-center"><Spinner animation="border" /></div>
          ) : pendingRequests.length === 0 ? (
            <p className="text-muted">No pending requests.</p>
          ) : (
            <ListGroup className="mb-4">
              {pendingRequests.map((req) => (
                <ListGroup.Item key={req.id} className="d-flex justify-content-between align-items-center">
                  {req.username}
                  <Button variant="success" size="sm" onClick={() => handleAcceptRequest(req.id, req.username)}>
                    Accept
                  </Button>
                </ListGroup.Item>
              ))}
            </ListGroup>
          )}

          <hr className="my-4" />

          {/* Your Friends Section */}
          <h4 className="mb-3">Your Friends</h4>
          {loading ? (
            <div className="text-center"><Spinner animation="border" /></div>
          ) : friends.length === 0 ? (
            <p className="text-muted">You don't have any friends yet.</p>
          ) : (
            <ListGroup>
              {friends.map((friend) => (
                <ListGroup.Item key={friend.id} className="d-flex justify-content-between align-items-center">
                  {friend.username}
                  <Button variant="info" size="sm" onClick={() => handleGoToChat(friend.id, friend.username)}>
                    Chat
                  </Button>
                </ListGroup.Item>
              ))}
            </ListGroup>
          )}
        </Card.Body>
      </Card>
    </Container>
  );
}

export default DashboardPage;