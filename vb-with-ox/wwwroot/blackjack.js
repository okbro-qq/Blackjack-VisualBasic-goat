// Blackjack Game Logic
let deck = [];
let playerHand = [];
let dealerHand = [];
let gameActive = false;

// Card values and suits
const suits = ['♠', '♥', '♦', '♣'];
const values = ['A', '2', '3', '4', '5', '6', '7', '8', '9', '10', 'J', 'Q', 'K'];

// Initialize deck
function createDeck() {
    deck = [];
    for (let suit of suits) {
        for (let value of values) {
            deck.push({ value, suit, numValue: getCardValue(value) });
        }
    }
    shuffleDeck();
}

// Shuffle deck using Fisher-Yates algorithm
function shuffleDeck() {
    for (let i = deck.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [deck[i], deck[j]] = [deck[j], deck[i]];
    }
}

// Get numeric value of card
function getCardValue(value) {
    if (value === 'A') return 11;
    if (['J', 'Q', 'K'].includes(value)) return 10;
    return parseInt(value);
}

// Calculate hand total (handles Ace as 1 or 11)
function calculateTotal(hand) {
    let total = 0;
    let aces = 0;
    
    for (let card of hand) {
        total += card.numValue;
        if (card.value === 'A') aces++;
    }
    
    // Adjust for Aces
    while (total > 21 && aces > 0) {
        total -= 10;
        aces--;
    }
    
    return total;
}

// Render cards to UI
function renderHand(hand, elementId, hideFirst = false) {
    const container = document.getElementById(elementId);
    container.innerHTML = '';
    
    hand.forEach((card, index) => {
        const cardDiv = document.createElement('div');
        cardDiv.className = 'card';
        
        // Hide dealer's first card until game ends
        if (hideFirst && index === 0) {
            cardDiv.textContent = '?';
            cardDiv.style.background = '#95a5a6';
        } else {
            cardDiv.textContent = card.value + card.suit;
            if (card.suit === '♥' || card.suit === '♦') {
                cardDiv.classList.add('red');
            }
        }
        
        container.appendChild(cardDiv);
    });
}

// Update total display
function updateTotals(showDealer = false) {
    const playerTotal = calculateTotal(playerHand);
    document.getElementById('player-total').textContent = `Total: ${playerTotal}`;
    
    if (showDealer) {
        const dealerTotal = calculateTotal(dealerHand);
        document.getElementById('dealer-total').textContent = `Total: ${dealerTotal}`;
    } else {
        // Only show dealer's visible card
        if (dealerHand.length > 1) {
            const visibleCard = dealerHand[1];
            document.getElementById('dealer-total').textContent = `Showing: ${visibleCard.numValue}`;
        }
    }
}

// Deal initial cards
function dealCards() {
    createDeck();
    playerHand = [];
    dealerHand = [];
    gameActive = true;
    
    // Deal 2 cards to each
    playerHand.push(deck.pop());
    dealerHand.push(deck.pop());
    playerHand.push(deck.pop());
    dealerHand.push(deck.pop());
    
    renderHand(playerHand, 'player-cards');
    renderHand(dealerHand, 'dealer-cards', true);
    updateTotals(false);
    
    // Enable game buttons
    document.getElementById('deal-btn').disabled = true;
    document.getElementById('hit-btn').disabled = false;
    document.getElementById('stand-btn').disabled = false;
    
    // Clear result
    const resultDiv = document.getElementById('result');
    resultDiv.textContent = '';
    resultDiv.className = 'result';
    
    // Check for blackjack
    if (calculateTotal(playerHand) === 21) {
        stand();
    }
}

// Player hits
function hit() {
    if (!gameActive) return;
    
    playerHand.push(deck.pop());
    renderHand(playerHand, 'player-cards');
    updateTotals(false);
    
    const playerTotal = calculateTotal(playerHand);
    
    // Check for bust
    if (playerTotal > 21) {
        endGame('Player busts! Dealer wins.', 'lose');
    } else if (playerTotal === 21) {
        stand();
    }
}

// Player stands
function stand() {
    if (!gameActive) return;
    
    gameActive = false;
    
    // Reveal dealer's cards
    renderHand(dealerHand, 'dealer-cards', false);
    
    // Dealer draws to 17
    while (calculateTotal(dealerHand) < 17) {
        dealerHand.push(deck.pop());
        renderHand(dealerHand, 'dealer-cards', false);
    }
    
    updateTotals(true);
    
    // Determine winner
    const playerTotal = calculateTotal(playerHand);
    const dealerTotal = calculateTotal(dealerHand);
    
    if (dealerTotal > 21) {
        endGame('Dealer busts! Player wins!', 'win');
    } else if (playerTotal > dealerTotal) {
        endGame('Player wins!', 'win');
    } else if (dealerTotal > playerTotal) {
        endGame('Dealer wins!', 'lose');
    } else {
        endGame('Push! It\'s a tie.', 'push');
    }
}

// End game
function endGame(message, resultClass) {
    gameActive = false;
    
    const resultDiv = document.getElementById('result');
    resultDiv.textContent = message;
    resultDiv.className = `result ${resultClass}`;
    
    // Disable game buttons
    document.getElementById('hit-btn').disabled = true;
    document.getElementById('stand-btn').disabled = true;
    document.getElementById('deal-btn').disabled = false;
    
    // Show dealer's full hand
    renderHand(dealerHand, 'dealer-cards', false);
    updateTotals(true);
}

// Initialize on page load
console.log('Blackjack game loaded successfully!');
