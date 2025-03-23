import random
import os  # Import the 'os' module
import base58
import logging
import hashlib
import ecdsa
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
import mysql.connector
import bcrypt
from eth_keys import keys
from decimal import Decimal  # Ensure Decimal is imported
import requests  # Import requests for fetching price

app = Flask(__name__)
app.secret_key = os.urandom(24)  # use it

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Database Configuration
DB_HOST = "localhost"
DB_USER = "root"
DB_PASSWORD = "akshay"
DB_NAME = "cryptowallet"


def get_db_connection():
    """Safely connect to the database."""
    try:
        conn = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME,
            charset='utf8mb4',
            collation='utf8mb4_unicode_ci'
        )
        logging.info("Database connection successful")
        return conn
    except mysql.connector.Error as e:
        logging.error(f"Database connection error: {e}")
        return None


# ✅ Generate Bitcoin Wallet
def generate_btc_wallet():
    private_key = os.urandom(32)
    sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    public_key = b'\x04' + vk.to_string()

    sha256_hash = hashlib.sha256(public_key).digest()
    ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()

    network_byte = b'\x00'
    extended_ripemd160_hash = network_byte + ripemd160_hash

    double_sha256 = hashlib.sha256(hashlib.sha256(extended_ripemd160_hash).digest()).digest()
    checksum = double_sha256[:4]

    address = base58.b58encode(extended_ripemd160_hash + checksum).decode('ascii')

    return private_key.hex(), public_key.hex(), address


# ✅ Generate Ethereum Wallet
def generate_eth_wallet():
    private_key = os.urandom(32)
    eth_private_key = keys.PrivateKey(private_key)
    public_key = eth_private_key.public_key
    address = public_key.to_checksum_address()
    return private_key.hex(), public_key.to_hex(), address


# ✅ Home Route
@app.route('/')
def home():
    isLoggedIn = 'user_id' in session
    user_data = {
        'firstname': session.get('firstname', ''),
        'lastname': session.get('lastname', ''),
        'username': session.get('username', ''),
        'email': session.get('email', ''),
    }

    btc_address = eth_address = usdt_address = None
    if isLoggedIn:
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor(dictionary=True)
            try:
                cursor.execute("SELECT currency_type, wallet_address FROM wallets WHERE user_id = %s",
                               (session['user_id'],))
                wallets = cursor.fetchall()

                for wallet in wallets:
                    if wallet['currency_type'] == 'BTC':
                        btc_address = wallet['wallet_address']
                    elif wallet['currency_type'] == 'ETH':
                        eth_address = wallet['wallet_address']
                    elif wallet['currency_type'] == 'USDT':
                        usdt_address = wallet['wallet_address']
            finally:
                cursor.close()
                conn.close()

    return render_template('home.html', isLoggedIn=isLoggedIn, **user_data, btc_address=btc_address,
                           eth_address=eth_address,
                           usdt_address=usdt_address)


# ✅ Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json()
        email, password = data.get('email'), data.get('password')

        if not email or not password:
            return jsonify({'error': "Email and password required"}), 400

        conn = get_db_connection()
        if not conn:
            return jsonify({'error': "Database connection failed"}), 500

        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()

            if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
                session.update({key: user[key] for key in ['user_id', 'username', 'firstname', 'lastname', 'email']})
                return jsonify({'message': 'Login successful', 'redirect': url_for('dashboard')}), 200  # Redirect to dashboard after login
            return jsonify({'error': "Invalid credentials"}), 401
        finally:
            cursor.close()
            conn.close()

    return render_template('login.html')


# ✅ Register Route (Auto Redirect to Login) - CORRECTED + USDT ADDRESS GENERATION
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    firstname, lastname, email, password, username = data.get('firstname'), data.get('lastname'), data.get('email'), data.get('password'), data.get('username')

    if not all([firstname, lastname, email, password, username]):
        flash('All fields are required', 'error')
        return redirect(url_for('register'))

    conn = get_db_connection()
    if not conn:
        flash("Database connection failed", "error")
        return redirect(url_for('register'))

    cursor = conn.cursor()
    try:
        cursor.execute("SELECT user_id FROM users WHERE email = %s OR username = %s", (email, username))
        if cursor.fetchone():
            flash("Email or username already exists", "error")
            return redirect(url_for('register'))

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        cursor.execute("INSERT INTO users (firstname, lastname, email, password, username) VALUES (%s, %s, %s, %s, %s)",
                       (firstname, lastname, email, hashed_password, username))
        user_id = cursor.lastrowid

        btc_private, btc_public, btc_address = generate_btc_wallet()
        eth_private, eth_public, eth_address = generate_eth_wallet()
        usdt_private, usdt_public, usdt_address = generate_eth_wallet()  # ✅ Generate USDT address using Ethereum wallet generation

        wallets = [('BTC', btc_address, btc_private, btc_public),
                   ('ETH', eth_address, eth_private, eth_public),
                   ('USDT', usdt_address, usdt_private, usdt_public)]  # ✅ Include USDT wallet info
        for currency, address, private_key, public_key in wallets:
            cursor.execute(
                "INSERT INTO wallets (user_id, currency_type, wallet_address, private_key, public_key) VALUES (%s, %s, %s, %s, %s)",
                (user_id, currency, address, private_key, public_key))

        # *** ENSURE THIS PART IS PRESENT AND CORRECT ***
        for currency in ["BTC", "ETH", "USDT"]:
            cursor.execute("INSERT INTO balances (user_id, currency_type, balance) VALUES (%s, %s, 0.0)",
                           (user_id, currency))
        conn.commit()
        # *** COMMIT IS CRUCIAL AFTER BALANCE INSERTS ***

        flash("Registration successful! Please log in.", "success")
        return redirect(url_for('login'))  # ✅ Redirects to login page

    finally:
        cursor.close()
        conn.close()


# ✅ Dashboard Route
def get_binance_price(symbol):
    """Fetch real-time price of a cryptocurrency from Binance API"""
    try:
        url = f"https://api.binance.com/api/v3/ticker/price?symbol={symbol}"
        response = requests.get(url)
        data = response.json()
        return float(data['price'])
    except Exception as e:
        logging.error(f"Error fetching price for {symbol}: {e}")
        return None  # Return None if API call fails


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = get_db_connection()
    if not conn:
        flash("Database connection failed", "error")
        return render_template('dashboard.html', total_balance=0, username=session['username'], assets=[])

    cursor = conn.cursor(dictionary=True)
    try:
        # Fetch balances for each currency
        cursor.execute("SELECT currency_type, balance FROM balances WHERE user_id = %s", (user_id,))
        balances = {row['currency_type']: float(row['balance']) for row in cursor.fetchall()}

        # ✅ Get live prices from Binance
        btc_price_usd = get_binance_price("BTCUSDT") or 60000  # Default to 60k if API fails
        eth_price_usd = get_binance_price("ETHUSDT") or 3000  # Default to 3k if API fails
        usdt_price_usd = 1.0  # USDT is pegged to USD

        # ✅ Calculate total balance dynamically
        btc_balance = balances.get('BTC', 0.0)
        eth_balance = balances.get('ETH', 0.0)
        usdt_balance = balances.get('USDT', 0.0)

        total_balance_usd = (btc_balance * btc_price_usd) + (eth_balance * eth_price_usd) + usdt_balance * usdt_price_usd

        # ✅ Asset details for display
        assets = []
        if btc_balance > 0:
            assets.append({
                "name": "Bitcoin",
                "symbol": "BTC",
                "quantity": btc_balance,
                "value": btc_balance * btc_price_usd,
                "logo_url": "https://assets.coingecko.com/coins/images/1/small/bitcoin.png?1547033579",
                "coingecko_id": "bitcoin"
            })
        if eth_balance > 0:
            assets.append({
                "name": "Ethereum",
                "symbol": "ETH",
                "quantity": eth_balance,
                "value": eth_balance * eth_price_usd,
                "logo_url": "https://assets.coingecko.com/coins/images/279/small/ethereum.png?1595348880",
                "coingecko_id": "ethereum"
            })
        if usdt_balance > 0:  # ✅ Add USDT to assets list
            assets.append({
                "name": "Tether",
                "symbol": "USDT",
                "quantity": usdt_balance,
                "value": usdt_balance * usdt_price_usd,
                "logo_url": "https://upload.wikimedia.org/wikipedia/en/thumb/9/94/Usdt_logo.svg/480px-Usdt_logo.svg.png",
                # Replace with correct USDT logo URL if needed
                "coingecko_id": "tether"  # Add coingecko id for USDT
            })

        return render_template('dashboard.html', total_balance=total_balance_usd, username=session['username'],
                               assets=assets)

    except Exception as e:
        logging.error(f"Error fetching dashboard data: {e}")
        flash("Error fetching dashboard data. Please try again.", "error")
        return render_template('dashboard.html', total_balance=0, username=session['username'], assets=[])

    finally:
        cursor.close()
        conn.close()


# ✅ Extra Routes
@app.route('/send')
def send():
    return render_template('send.html')


@app.route('/buycrypto')
def buycrypto():
    return render_template('buycrypto.html')


# ✅ Logout
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))


# ✅ Buy Crypto Route - FIXED code from user
@app.route('/buy_crypto', methods=['POST'])
def buy_crypto():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401

    data = request.get_json()
    currency_type = data.get('currency_type')
    quantity = data.get('quantity')

    if not currency_type or not quantity:
        return jsonify({'error': 'Currency type and quantity are required'}), 400

    if currency_type not in ['BTC', 'ETH', 'USDT']:
        return jsonify({'error': 'Invalid currency type'}), 400

    user_id = session['user_id']
    conn = get_db_connection()

    if conn is None:
        return jsonify({'error': "Failed to connect to database."}), 500

    cursor = conn.cursor()

    try:
        # Check if user exists
        cursor.execute("SELECT 1 FROM users WHERE user_id = %s", (user_id,))

        if cursor.fetchone() is None:
            conn.rollback()
            return jsonify({'error': 'User not found'}), 404  # Fixed syntax here

        try:
            quantity = float(quantity)
        except ValueError:
            return jsonify({'error': 'Invalid quantity format'}), 400

        if quantity <= 0:
            return jsonify({'error': 'Quantity must be positive'}), 400

        # Check if balance record exists
        cursor.execute("SELECT 1 FROM balances WHERE user_id = %s AND currency_type = %s",
                       (user_id, currency_type))

        if cursor.fetchone() is None:
            conn.rollback()
            return jsonify({'error': 'Balances record not found'}), 404  # Fixed syntax here

        # Update balance
        cursor.execute(
            "UPDATE balances SET balance = balance + %s WHERE user_id = %s AND currency_type = %s",
            (quantity, user_id, currency_type)
        )

        # Commit changes
        conn.commit()

        # Get updated balance
        cursor.execute(
            "SELECT balance FROM balances WHERE user_id = %s AND currency_type = %s",
            (user_id, currency_type)
        )
        result = cursor.fetchone()

        if not result:
            conn.rollback()
            return jsonify({'error': 'Could not retrieve balance'}), 500

        # Convert Decimal to float explicitly
        from decimal import Decimal
        new_balance = result[0]
        new_balance_float = float(new_balance) if new_balance is not None else 0.0

        return jsonify({
            'message': f"Successfully purchased {quantity} {currency_type}",
            'new_balance': new_balance_float
        }), 200

    except Exception as e:
        if conn:
            conn.rollback()
        logging.error(f"Transaction failed: {e}")
        return jsonify({'error': f"Transaction failed. Could not update balance."}), 500  # Fixed syntax here

    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


# ✅ Swap Route
@app.route('/swap')
def swap():
    return render_template('swap.html')


# ✅ Run App
if __name__ == '__main__':
    app.run(debug=True)