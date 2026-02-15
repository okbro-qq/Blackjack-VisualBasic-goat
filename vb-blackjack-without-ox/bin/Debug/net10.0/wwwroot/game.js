// Blackjack Game Logic
class BlackjackGame {
    constructor() {
        this.deck = [];
        this.playerHand = [];
        this.dealerHand = [];
        this.gameOver = false;
        
        this.dealBtn = document.getElementById('deal-btn');
        this.hitBtn = document.getElementById('hit-btn');
        this.standBtn = document.getElementById('stand-btn');
        
        this.playerCardsEl = document.getElementById('player-cards');
        this.dealerCardsEl = document.getElementById('dealer-cards');
        this.playerTotalEl = document.getElementById('player-total');
        this.dealerTotalEl = document.getElementById('dealer-total');
        this.resultEl = document.getElementById('result');
        
        this.setupEventListeners();
    }
    
    setupEventListeners() {
        this.dealBtn.addEventListener('click', () => this.deal());
        this.hitBtn.addEventListener('click', () => this.hit());
        this.standBtn.addEventListener('click', () => this.stand());
    }
    
    createDeck() {
        const suits = ['♠', '♥', '♦', '♣'];
        const values = ['A', '2', '3', '4', '5', '6', '7', '8', '9', '10', 'J', 'Q', 'K'];
        this.deck = [];
        
        for (let suit of suits) {
            for (let value of values) {
                this.deck.push({
                    suit: suit,
                    value: value,
                    isRed: suit === '♥' || suit === '♦'
                });
            }
        }
        
        // Shuffle deck
        for (let i = this.deck.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [this.deck[i], this.deck[j]] = [this.deck[j], this.deck[i]];
        }
    }
    
    drawCard() {
        return this.deck.pop();
    }
    
    getCardValue(card) {
        if (card.value === 'A') return 11;
        if (['J', 'Q', 'K'].includes(card.value)) return 10;
        return parseInt(card.value);
    }
    
    calculateHandValue(hand) {
        let value = 0;
        let aces = 0;
        
        for (let card of hand) {
            value += this.getCardValue(card);
            if (card.value === 'A') aces++;
        }
        
        // Adjust for aces
        while (value > 21 && aces > 0) {
            value -= 10;
            aces--;
        }
        
        return value;
    }
    
    renderCard(card, hidden = false) {
        const cardEl = document.createElement('div');
        cardEl.className = 'card' + (hidden ? ' hidden' : card.isRed ? ' red' : '');
        cardEl.textContent = hidden ? '?' : `${card.value}${card.suit}`;
        return cardEl;
    }
    
    renderHands(hideDealerCard = false) {
        // Render player cards
        this.playerCardsEl.innerHTML = '';
        for (let card of this.playerHand) {
            this.playerCardsEl.appendChild(this.renderCard(card));
        }
        
        // Render dealer cards
        this.dealerCardsEl.innerHTML = '';
        for (let i = 0; i < this.dealerHand.length; i++) {
            const isHidden = hideDealerCard && i === 1;
            this.dealerCardsEl.appendChild(this.renderCard(this.dealerHand[i], isHidden));
        }
        
        // Update totals
        const playerValue = this.calculateHandValue(this.playerHand);
        this.playerTotalEl.textContent = `Total: ${playerValue}`;
        
        if (hideDealerCard) {
            const firstCardValue = this.getCardValue(this.dealerHand[0]);
            this.dealerTotalEl.textContent = `Total: ${firstCardValue}`;
        } else {
            const dealerValue = this.calculateHandValue(this.dealerHand);
            this.dealerTotalEl.textContent = `Total: ${dealerValue}`;
        }
    }
    
    deal() {
        this.createDeck();
        this.playerHand = [];
        this.dealerHand = [];
        this.gameOver = false;
        this.resultEl.textContent = '';
        
        // Deal initial cards
        this.playerHand.push(this.drawCard());
        this.dealerHand.push(this.drawCard());
        this.playerHand.push(this.drawCard());
        this.dealerHand.push(this.drawCard());
        
        this.renderHands(true);
        
        // Check for blackjack
        if (this.calculateHandValue(this.playerHand) === 21) {
            this.stand();
        } else {
            this.dealBtn.disabled = true;
            this.hitBtn.disabled = false;
            this.standBtn.disabled = false;
        }
    }
    
    hit() {
        if (this.gameOver) return;
        
        this.playerHand.push(this.drawCard());
        this.renderHands(true);
        
        const playerValue = this.calculateHandValue(this.playerHand);
        if (playerValue > 21) {
            this.endGame('Player busts! Dealer wins!');
        } else if (playerValue === 21) {
            this.stand();
        }
    }
    
    stand() {
        if (this.gameOver) return;
        
        // Reveal dealer's hidden card
        this.renderHands(false);
        
        // Dealer draws to 17
        while (this.calculateHandValue(this.dealerHand) < 17) {
            this.dealerHand.push(this.drawCard());
            this.renderHands(false);
        }
        
        // Determine winner
        const playerValue = this.calculateHandValue(this.playerHand);
        const dealerValue = this.calculateHandValue(this.dealerHand);
        
        if (dealerValue > 21) {
            this.endGame('Dealer busts! Player wins!');
        } else if (playerValue > dealerValue) {
            this.endGame('Player wins!');
        } else if (dealerValue > playerValue) {
            this.endGame('Dealer wins!');
        } else {
            this.endGame('Push! It\'s a tie!');
        }
    }
    
    endGame(message) {
        this.gameOver = true;
        this.resultEl.textContent = message;
        this.hitBtn.disabled = true;
        this.standBtn.disabled = true;
        this.dealBtn.disabled = false;
        
        // Record the game result
        let result = 'push';
        if (message.includes('Player wins') || message.includes('Dealer busts')) {
            result = 'player';
        } else if (message.includes('Dealer wins') || message.includes('Player busts')) {
            result = 'dealer';
        }
        
        // Send result to server
        fetch('/game/record', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: `result=${result}`
        }).catch(err => console.error('Failed to record game:', err));
    }
}

// Initialize game when page loads
document.addEventListener('DOMContentLoaded', () => {
    const game = new BlackjackGame();
});
