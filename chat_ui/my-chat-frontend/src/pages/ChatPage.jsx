import React, { useState, useEffect, useRef, useCallback } from 'react';
import { Container, Card, Row, Col, Button, Form, Spinner, Alert, Modal } from 'react-bootstrap';
import { useParams, useLocation, useNavigate } from 'react-router-dom';
import { io } from 'socket.io-client';

import { embedImage, extractImage, getMessages } from '../api'; 

// Helper function to convert File to Base64 (needed for image uploads)
const fileToBase64 = (file) => {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.readAsDataURL(file);
        reader.onload = () => resolve(reader.result.split(',')[1]); // Get only the base64 part
        reader.onerror = error => reject(error);
    });
};

const API_BASE_URL_FOR_SOCKET = 'http://127.0.0.1:5000';

function ChatPage() {
    const { userId } = useParams();
    const location = useLocation();
    const navigate = useNavigate();
    const friendUsername = location.state?.friendUsername || 'Friend';
    const currentUserId = localStorage.getItem('user_id'); 
    const currentUsername = localStorage.getItem('username'); // For display

    const [messageInput, setMessageInput] = useState(''); 
    const [secretMessageInput, setSecretMessageInput] = useState(''); 
    const [chatMessages, setChatMessages] = useState([]);
    const [socket, setSocket] = useState(null);
    const messagesEndRef = useRef(null);
    const [loadingHistory, setLoadingHistory] = useState(true);
    const [uploadingImage, setUploadingImage] = useState(false);

    const [selectedImageFile, setSelectedImageFile] = useState(null);
    const [extractedMessage, setExtractedMessage] = useState('');
    const [showExtractModal, setShowExtractModal] = useState(false);
    // Ensure extractionPayload default has algorithm if it might be null from history
    const [extractionPayload, setExtractionPayload] = useState({ imageBase64: null, key: null, algorithm: 'aes' }); 
    const [extracting, setExtracting] = useState(false);

    // Set default and only option for image encryption to AES
    const [selectedAlgorithm, setSelectedAlgorithm] = useState('aes'); 
    // encryptionAlgorithms array is no longer needed for selection on image upload
    // If you want to still allow other algorithms for *text* messages (if you implement that),
    // you would need more complex logic here. For image steganography, it's fixed to AES.

    // --- Auto-scroll to bottom ---
    const scrollToBottom = useCallback(() => {
        messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
    }, []);

    // --- Socket.IO Setup ---
    useEffect(() => {
        const token = localStorage.getItem('token');
        const newSocket = io(API_BASE_URL_FOR_SOCKET, {
            query: { 
                token: token 
            },
            transports: ['websocket', 'polling']
        });

        const handleReceiveMessage = (message) => {
            setChatMessages((prevMessages) => [...prevMessages, message]);
        };

        newSocket.on('connect', () => {
            if (currentUserId) {
                newSocket.emit('join_chat_room', { userId: currentUserId });
            }
        });

        newSocket.on('receive_message', handleReceiveMessage);

        newSocket.on('error', (data) => {
            console.error('Socket Error:', data.message);
            if (data.message.includes('Authentication failed')) {
                alert('Socket authentication failed. Please log in again.');
                navigate('/login');
            }
        });

        newSocket.on('disconnect', (reason) => {
            console.log('Socket Disconnected:', reason);
        });

        setSocket(newSocket);

        return () => {
            newSocket.off('receive_message', handleReceiveMessage);
            newSocket.disconnect();
        };
    }, [currentUserId, navigate]);

    // --- Fetch Chat History ---
    useEffect(() => {
        const fetchHistory = async () => {
            setLoadingHistory(true);
            try {
                const history = await getMessages(userId); 
                setChatMessages(history);
            } catch (error) {
                console.error('Error fetching chat history:', error);
                alert('Could not load chat history. ' + error.message);
            } finally {
                setLoadingHistory(false);
            }
        };

        if (socket && userId) {
            fetchHistory();
        }
    }, [userId, socket]);

    // --- Scroll to bottom when messages update ---
    useEffect(() => {
        scrollToBottom();
    }, [chatMessages, scrollToBottom]);


    // --- Send Message Handler ---
    const handleSendMessage = async (e) => {
        e.preventDefault();

        if (!socket || !socket.connected) {
            alert('Socket not connected. Please refresh or check connection.');
            return;
        }

        if (selectedImageFile) {
            // --- Handle Image Steganography Send ---
            if (!secretMessageInput.trim()) {
                alert('Please enter the secret message to hide in the image.');
                return;
            }
            setUploadingImage(true);
            try {
                // selectedAlgorithm is already set to 'aes' when image is chosen
                const result = await embedImage(selectedImageFile, secretMessageInput, selectedAlgorithm); 
                
                if (result.steganographed_file_base64) {
                    const messagePayload = {
                        sender_id: currentUserId,
                        recipient_id: userId,
                        message_type: 'image',
                        content: result.steganographed_file_base64,
                        key_for_decryption: result.encryption_key_hex,
                        encryption_algorithm: selectedAlgorithm // Will be 'aes'
                    };
                    console.log("DEBUG: Emitting 'send_message' (image payload):", messagePayload);
                    socket.emit(
                        'send_message', 
                        messagePayload
                    );
                    setSelectedImageFile(null);
                    setSecretMessageInput('');
                } else {
                    alert(result.error || 'Image embedding failed.');
                }
            } catch (error) {
                console.error('Image upload error:', error);
                alert('Failed to embed and send image. Check console.');
            } finally {
                setUploadingImage(false);
            }
        } else if (messageInput.trim()) {
            // --- Handle Text Message Send ---
            const messagePayload = {
                sender_id: currentUserId,
                recipient_id: userId,
                message_type: 'text',
                content: messageInput,
                encryption_algorithm: null 
            };
            console.log("DEBUG: Emitting 'send_message' (text payload):", messagePayload);
            socket.emit('send_message', messagePayload);
            setMessageInput('');
        }
    };

    // --- Image Selection Handler ---
    const handleImageSelect = (e) => {
        const file = e.target.files[0];
        if (file) {
            setSelectedImageFile(file);
            setMessageInput(''); // Clear text message input when image is selected
            setSelectedAlgorithm('aes'); // Force AES when an image is selected
        }
    };

    // --- Extract Image Handler (for received messages) ---
    const handleExtractImage = async () => {
        if (!extractionPayload.imageBase64 || !extractionPayload.key || !extractionPayload.algorithm) {
            alert('No image, key, or algorithm available for extraction.');
            return;
        }
        setExtracting(true);
        setExtractedMessage(''); 

        try {
            // Convert base64 back to File for the extractImage API helper
            const byteCharacters = atob(extractionPayload.imageBase64);
            const byteNumbers = new Array(byteCharacters.length);
            for (let i = 0; i < byteCharacters.length; i++) {
                byteNumbers[i] = byteCharacters.charCodeAt(i);
            }
            const byteArray = new Uint8Array(byteNumbers);
            const blob = new Blob([byteArray], { type: 'image/png' }); 
            const fileToExtract = new File([blob], "stego_image.png", { type: 'image/png' });

            // Pass the received algorithm to extractImage
            const result = await extractImage(fileToExtract, extractionPayload.key, extractionPayload.algorithm); 

            if (result.secret_message) {
                setExtractedMessage(result.secret_message);
            } else {
                setExtractedMessage(result.error || 'Decryption failed. Incorrect key or algorithm?');
            }
        } catch (error) {
            console.error('Image extraction error:', error);
            setExtractedMessage(`Error during extraction: ${error.message}`);
        } finally {
            setExtracting(false);
        }
    };


    return (
        <Container className="my-5">
            {/* This is the main chat card */}
            <Card className="p-4 shadow">
                <Card.Header className="d-flex justify-content-between align-items-center">
                    <Button variant="link" onClick={() => navigate('/dashboard')} className="p-0">
                        &larr; Back
                    </Button>
                    <h4 className="mb-0 flex-grow-1 text-center">Chat with {friendUsername}</h4>
                    <div style={{width: '60px'}}></div> 
                </Card.Header>

                <Card.Body style={{ minHeight: '400px', maxHeight: '400px', overflowY: 'auto', display: 'flex', flexDirection: 'column' }}>
                    {loadingHistory ? (
                        <div className="text-center my-auto"><Spinner animation="border" /> <p>Loading history...</p></div>
                    ) : chatMessages.length === 0 ? (
                        <p className="text-muted text-center my-auto">Start chatting!</p>
                    ) : (
                        <>
                            {chatMessages.map((msg, index) => (
                                <Row key={msg.id || index} className={`mb-2 ${parseInt(msg.sender_id) === parseInt(currentUserId) ? 'justify-content-end' : 'justify-content-start'}`}>
                                    <Col xs={10} sm={8} md={6}>
                                        <Card 
                                            className={`p-2 ${parseInt(msg.sender_id) === parseInt(currentUserId) ? 'bg-primary text-white' : 'bg-light'}`}
                                        >
                                            {msg.message_type === 'text' ? (
                                                <Card.Text className="mb-0" style={{ wordBreak: 'break-word' }}>{msg.content}</Card.Text>
                                            ) : (
                                                <>
                                                    <Card.Img 
                                                        src={`data:image/png;base64,${msg.content}`} 
                                                        alt="Steganographed Image" 
                                                        className="mb-2" 
                                                        onClick={() => {
                                                            setExtractionPayload({ 
                                                                imageBase64: msg.content, 
                                                                key: msg.key_for_decryption,
                                                                // Ensure algorithm defaults if it somehow was null from older messages
                                                                algorithm: msg.encryption_algorithm || 'aes' 
                                                            });
                                                            setExtractedMessage(''); 
                                                            setShowExtractModal(true);
                                                        }}
                                                        style={{ cursor: 'pointer', maxWidth: '100%', height: 'auto' }}
                                                    />
                                                    <Button 
                                                        variant={parseInt(msg.sender_id) === parseInt(currentUserId) ? 'outline-light' : 'outline-dark'} 
                                                        size="sm" 
                                                        onClick={() => {
                                                            setExtractionPayload({ 
                                                                imageBase64: msg.content, 
                                                                key: msg.key_for_decryption,
                                                                // Ensure algorithm defaults if it somehow was null from older messages
                                                                algorithm: msg.encryption_algorithm || 'aes' 
                                                            });
                                                            setExtractedMessage(''); 
                                                            setShowExtractModal(true);
                                                        }}
                                                    >
                                                        Click to Extract Message (Algo: {msg.encryption_algorithm ? msg.encryption_algorithm.toUpperCase() : 'AES'})
                                                    </Button>
                                                </>
                                            )}
                                            <small className={`text-end ${parseInt(msg.sender_id) === parseInt(currentUserId) ? 'text-white-50' : 'text-muted'}`}>
                                                {parseInt(msg.sender_id) === parseInt(currentUserId) ? currentUsername : friendUsername} - {new Date(msg.timestamp).toLocaleTimeString()}
                                            </small>
                                        </Card>
                                    </Col>
                                </Row>
                            ))}
                            <div ref={messagesEndRef} />
                        </>
                    )}
                </Card.Body>

                <Card.Footer>
                    <Form onSubmit={handleSendMessage}>
                        <Row className="align-items-center mb-2">
                            <Col>
                                <Form.Label className="mb-0">Encryption Algorithm:</Form.Label>
                                {/* Display AES as read-only for image uploads */}
                                <Form.Control
                                    type="text"
                                    value="AES" // Always display AES
                                    readOnly // Make it read-only
                                    disabled={selectedImageFile} // Disable if an image is selected
                                />
                                {/* The actual dropdown for algorithm selection is removed here */}
                            </Col>
                        </Row>
                        <Row className="align-items-center">
                            <Col>
                                <Form.Control
                                    type="text"
                                    placeholder={selectedImageFile ? "Enter secret message to hide..." : "Type your message..."}
                                    value={selectedImageFile ? secretMessageInput : messageInput}
                                    onChange={(e) => selectedImageFile ? setSecretMessageInput(e.target.value) : setMessageInput(e.target.value)}
                                    disabled={uploadingImage}
                                />
                            </Col>
                            <Col xs="auto">
                                <Button variant="primary" type="submit" disabled={uploadingImage || (selectedImageFile ? !secretMessageInput.trim() : !messageInput.trim())}>
                                    {uploadingImage ? <Spinner animation="border" size="sm" /> : 'Send'}
                                </Button>
                            </Col>
                            <Col xs="auto">
                                <Form.Label htmlFor="imageUpload" className="mb-0">
                                    <Button variant="outline-secondary" as="span" disabled={uploadingImage || selectedImageFile}>
                                        Image
                                    </Button>
                                </Form.Label>
                                <Form.Control 
                                    type="file" 
                                    id="imageUpload" 
                                    accept="image/*" 
                                    onChange={handleImageSelect} 
                                    style={{ display: 'none' }} 
                                    disabled={uploadingImage}
                                />
                            </Col>
                        </Row>
                        {selectedImageFile && (
                            <Alert variant="info" className="mt-2 mb-0">
                                Image selected: {selectedImageFile.name}. Enter secret message above.
                                <Button variant="link" size="sm" onClick={() => setSelectedImageFile(null)}>Clear Image</Button>
                            </Alert>
                        )}
                    </Form>
                </Card.Footer>
            </Card> 

            {/* MODAL STARTS HERE - OUTSIDE THE MAIN CHAT CARD, BUT STILL IN CONTAINER */}
            <Modal show={showExtractModal} onHide={() => setShowExtractModal(false)} centered>
                <Modal.Header closeButton>
                    <Modal.Title>Extract Secret Message</Modal.Title>
                </Modal.Header>
                <Modal.Body>
                    <Alert variant="info" className="mt-3">
                        Click "Extract Message" to reveal the hidden text. Algorithm: {extractionPayload.algorithm ? extractionPayload.algorithm.toUpperCase() : 'N/A'}.
                    </Alert>
                    <Button variant="success" onClick={handleExtractImage} disabled={extracting}>
                        {extracting ? <Spinner animation="border" size="sm" /> : 'Extract Message'}
                    </Button>
                    {extractedMessage && (
                        <Alert variant="success" className="mt-3">
                            <strong>Secret Message:</strong> <br/> {extractedMessage}
                        </Alert>
                    )}
                </Modal.Body>
                <Modal.Footer>
                    <Button variant="secondary" onClick={() => setShowExtractModal(false)}>
                        Close
                    </Button>
                </Modal.Footer>
            </Modal> 

        </Container>
    );
}

export default ChatPage;