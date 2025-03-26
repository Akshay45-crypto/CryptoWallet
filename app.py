import random
import os
import base58
import logging
import hashlib
import ecdsa
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
import mysql.connector
import bcrypt
from eth_keys import keys
from decimal import Decimal
import requests
from flask import Flask, render_template, request, jsonify, session
import random
import smtplib
from flask_mail import Mail, Message
import mysql.connector
from werkzeug.security import generate_password_hash

app = Flask(__name__)
app.secret_key = os.urandom(24)

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

DB_HOST = "localhost"
DB_USER = "root"
DB_PASSWORD = "akshay"
DB_NAME = "cryptowallet"
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'akxxybacktest@gmail.com'
app.config['MAIL_PASSWORD'] = 'fhtmqvagblhbfmxv'  # Generate app password from Google
app.config['MAIL_DEFAULT_SENDER'] = 'your-email@gmail.com'
mail = Mail(app)

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
otp_storage = {}

@app.route('/forgot-password')
def forgot_password():
    return render_template('forgot_password.html')

@app.route('/send-otp', methods=['POST'])
def send_otp():
    data = request.json
    email = data.get('email')

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()

    if not user:
        return jsonify({'error': 'No email found!'}), 404

    otp = str(random.randint(100000, 999999))
    otp_storage[email] = otp  # Store OTP

    # Professional Email Formatting
    msg = Message("🔒 Password Reset - Pixel Vault", recipients=[email])
    msg.body = f"""
Dear User,

We received a request to reset your password for **Pixel Vault**. If you made this request, please use the **One-Time Password (OTP)** below to verify your identity:

🔑 **Your OTP:** {otp}

This OTP is valid for **10 minutes**. Please do not share it with anyone for security reasons.

Once verified, you’ll be able to set a new password for your account. If you did not request this change, please ignore this email or contact our support team immediately.

For assistance, reach out to us at **support@pixelvault.com**.

Stay secure,  
🚀 **The Pixel Vault Security Team**
    """
    try:
        mail.send(msg)
        return jsonify({'success': True, 'message': 'OTP sent to your email'})
    except Exception as e:
        return jsonify({'error': f"Failed to send email: {str(e)}"}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    data = request.json
    email = data.get('email')
    otp = data.get('otp')

    if otp_storage.get(email) == otp:
        return jsonify({'success': True})
    else:
        return jsonify({'error': 'Invalid OTP'}), 400

@app.route('/reset-password', methods=['POST'])
def reset_password():
    data = request.json
    email = data.get('email')
    new_password = data.get('password')

    if not email or not new_password:
        return jsonify({'error': 'Email and new password required'}), 400

    # ✅ Ensure bcrypt is used (NOT scrypt)
    hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET password = %s WHERE email = %s", (hashed_password, email))
    conn.commit()

    # Remove OTP after successful reset
    otp_storage.pop(email, None)

    return jsonify({'success': True, 'message': 'Password successfully updated'})
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


def generate_eth_wallet():
    private_key = os.urandom(32)
    eth_private_key = keys.PrivateKey(private_key)
    public_key = eth_private_key.public_key
    address = public_key.to_checksum_address()
    return private_key.hex(), public_key.to_hex(), address


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


import bcrypt
import hashlib
import base64

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

            if not user:
                return jsonify({'error': "Invalid credentials"}), 401

            stored_password = user['password']

            if stored_password.startswith("$2b$"):  # ✅ bcrypt hash
                if bcrypt.checkpw(password.encode('utf-8'), stored_password.encode('utf-8')):
                    session.update({key: user[key] for key in ['user_id', 'username', 'firstname', 'lastname', 'email']})
                    return jsonify({'message': 'Login successful', 'redirect': url_for('dashboard')}), 200
                return jsonify({'error': "Invalid credentials"}), 401

            elif stored_password.startswith("scrypt:"):  # ❌ scrypt hash (needs reset)
                return jsonify({'error': 'Your password needs to be reset due to a security update. Please reset your password.'}), 401

            return jsonify({'error': "Invalid credentials"}), 401

        finally:
            cursor.close()
            conn.close()

    return render_template('login.html')



@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
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
            usdt_private, usdt_public, usdt_address = generate_eth_wallet()

            wallets = [('BTC', btc_address, btc_private, btc_public),
                       ('ETH', eth_address, eth_private, eth_public),
                       ('USDT', usdt_address, usdt_private, usdt_public)]
            for currency, address, private_key, public_key in wallets:
                cursor.execute(
                    "INSERT INTO wallets (user_id, currency_type, wallet_address, private_key, public_key) VALUES (%s, %s, %s, %s, %s)",
                    (user_id, currency, address, private_key, public_key))

            for currency in ["BTC", "ETH", "USDT"]:
                cursor.execute("INSERT INTO balances (user_id, currency_type, balance) VALUES (%s, %s, 0.0)",
                               (user_id, currency))
            conn.commit()

            flash("Registration successful! Please log in.", "success")
            return redirect(url_for('login'))

        except Exception as e:
            conn.rollback()
            logging.error(f"Transaction failed: {e}")
            flash("Transaction failed. Could not register", "error")
            return jsonify({'error': f"Transaction failed: {str(e)}"}), 500

        finally:
            cursor.close()
            conn.close()
    return render_template('login.html')


def get_binance_price(symbol):
    """Fetch real-time price of a cryptocurrency from Binance API"""
    try:
        url = f"https://api.binance.com/api/v3/ticker/price?symbol={symbol}"
        response = requests.get(url)
        data = response.json()
        return float(data['price'])
    except Exception as e:
        logging.error(f"Error fetching price for {symbol}: {e}")
        return None


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
        cursor.execute("SELECT currency_type, balance FROM balances WHERE user_id = %s", (user_id,))
        balances = {row['currency_type']: float(row['balance']) for row in cursor.fetchall()}

        btc_price_usd = get_binance_price("BTCUSDT") or 60000
        eth_price_usd = get_binance_price("ETHUSDT") or 3000
        usdt_price_usd = 1.0

        btc_balance = balances.get('BTC', 0.0)
        eth_balance = balances.get('ETH', 0.0)
        usdt_balance = balances.get('USDT', 0.0)

        total_balance_usd = (btc_balance * btc_price_usd) + (eth_balance * eth_price_usd) + usdt_balance * usdt_price_usd

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
        if usdt_balance > 0:
            assets.append({
                "name": "Tether",
                "symbol": "USDT",
                "quantity": usdt_balance,
                "value": usdt_balance * usdt_price_usd,
                "logo_url": "https://upload.wikimedia.org/wikipedia/en/thumb/9/94/Usdt_logo.svg/480px-Usdt_logo.svg.png",
                "coingecko_id": "tether"
            })

        return render_template('dashboard.html', total_balance=total_balance_usd, username=session['username'],
                               assets=assets,
                               firstname=session.get('firstname', ''),
                               lastname=session.get('lastname', ''),
                               email=session.get('email', ''))

    except Exception as e:
        logging.error(f"Error fetching dashboard data: {e}")
        flash("Error fetching dashboard data. Please try again.", "error")
        return render_template('dashboard.html', total_balance=0, username=session['username'], assets=[])

    finally:
        cursor.close()
        conn.close()


@app.route('/send')
def send():
    return render_template('send.html')


@app.route('/buycrypto')
def buycrypto():
    return render_template('buycrypto.html')


@app.route('/receive')
def receive():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = get_db_connection()
    if not conn:
        flash("Database connection failed", "error")
        return render_template('receive.html', btc_address=None, eth_address=None, usdt_address=None, doge_address=None)

    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT currency_type, wallet_address
            FROM wallets
            WHERE user_id = %s AND currency_type IN ('BTC', 'ETH', 'USDT', 'Dogecoin')
            """,
            (user_id,)
        )
        wallets = cursor.fetchall()

        btc_address = next((w['wallet_address'] for w in wallets if w['currency_type'] == 'BTC'), None)
        eth_address = next((w['wallet_address'] for w in wallets if w['currency_type'] == 'ETH'), None)
        usdt_address = next((w['wallet_address'] for w in wallets if w['currency_type'] == 'USDT'), None)
        doge_address = next((w['wallet_address'] for w in wallets if w['currency_type'] == 'Dogecoin'), None)

        return render_template('receive.html', btc_address=btc_address, eth_address=eth_address,
                               usdt_address=usdt_address, doge_address=doge_address)

    except mysql.connector.Error as e:
        logging.error(f"Database error: {e}")
        flash("Error retrieving wallet addresses. Please try again.", "error")
        return render_template('receive.html', btc_address=None, eth_address=None, usdt_address=None, doge_address=None)

    finally:
        cursor.close()
        conn.close()


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))


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
        cursor.execute("SELECT 1 FROM users WHERE user_id = %s", (user_id,))

        if cursor.fetchone() is None:
            conn.rollback()
            return jsonify({'error': 'User not found'}), 404

        try:
            quantity = float(quantity)
        except ValueError:
            return jsonify({'error': 'Invalid quantity format'}), 400

        if quantity <= 0:
            return jsonify({'error': 'Quantity must be positive'}), 400

        cursor.execute("SELECT 1 FROM balances WHERE user_id = %s AND currency_type = %s",
                       (user_id, currency_type))

        if cursor.fetchone() is None:
            conn.rollback()
            return jsonify({'error': 'Balances record not found'}), 404

        cursor.execute(
            "UPDATE balances SET balance = balance + %s WHERE user_id = %s AND currency_type = %s",
            (quantity, user_id, currency_type)
        )

        conn.commit()

        cursor.execute(
            "SELECT balance FROM balances WHERE user_id = %s AND currency_type = %s",
            (user_id, currency_type)
        )
        result = cursor.fetchone()

        if not result:
            conn.rollback()
            return jsonify({'error': 'Could not retrieve balance'}), 500

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
        return jsonify({'error': f"Transaction failed. Could not update balance."}), 500

    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@app.route('/swap')
def swap():
    return render_template('swap.html')


@app.route('/send_crypto', methods=['POST'])
def send_crypto():
    if 'user_id' not in session:
        logging.warning("User not logged in for send_crypto")
        return jsonify({'error': 'Not logged in'}), 401

    data = request.get_json()
    currency_type = data.get('coin')
    amount = data.get('amount')
    receiver_address = data.get('receiverAddress')

    if not all([currency_type, amount, receiver_address]):
        return jsonify({'error': 'All fields are required'}), 400

    try:
        amount = float(amount)
        if amount <= 0:
            return jsonify({'error': 'Amount must be positive'}), 400
    except ValueError:
        return jsonify({'error': 'Invalid amount format'}), 400

    user_id = session['user_id']
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': "Failed to connect to database."}), 500

    cursor = conn.cursor()
    try:
        # Currency Mapping (Fix for 'Bitcoin' vs. 'BTC')
        currency_mapping = {
            "Bitcoin": "BTC",
            "Ethereum": "ETH",
            "Tether": "USDT"
        }
        currency_type = currency_mapping.get(currency_type, currency_type)  # Convert name if needed

        # Debugging logs
        logging.debug(f"User ID from session: {user_id}")
        logging.debug(f"Mapped Currency Type: {currency_type}")
        logging.debug(f"Receiver address from form: {receiver_address}")

        # Check Sender Wallet
        cursor.execute(
            "SELECT wallet_address FROM wallets WHERE user_id = %s AND currency_type = %s",
            (user_id, currency_type)
        )
        sender_wallet_result = cursor.fetchone()

        if not sender_wallet_result:
            logging.error(f"Sender wallet not found for user {user_id} and currency {currency_type}")
            return jsonify({'error': 'Sender wallet not found for this currency'}), 404

        sender_wallet_address = sender_wallet_result[0]
        logging.debug(f"Sender wallet address: {sender_wallet_address}")

        # Check Sender Balance
        cursor.execute(
            "SELECT balance FROM balances WHERE user_id = %s AND currency_type = %s",
            (user_id, currency_type)
        )
        sender_balance_result = cursor.fetchone()

        if not sender_balance_result:
            return jsonify({'error': 'Sender balance not found'}), 404

        sender_balance = float(sender_balance_result[0])
        logging.debug(f"Sender balance: {sender_balance}")

        if sender_balance < amount:
            return jsonify({'error': 'Insufficient balance'}), 400

        # Deduct Sender Balance
        cursor.execute(
            "UPDATE balances SET balance = balance - %s WHERE user_id = %s AND currency_type = %s",
            (amount, user_id, currency_type)
        )

        # Find Receiver in Database
        cursor.execute(
            "SELECT user_id FROM wallets WHERE wallet_address = %s AND currency_type = %s",
            (receiver_address, currency_type)
        )
        receiver_wallet_result = cursor.fetchone()

        if receiver_wallet_result:
            receiver_user_id = receiver_wallet_result[0]
            logging.debug(f"Receiver user ID: {receiver_user_id}")

            # Add Amount to Receiver Balance
            cursor.execute(
                "UPDATE balances SET balance = balance + %s WHERE user_id = %s AND currency_type = %s",
                (amount, receiver_user_id, currency_type)
            )
        else:
            logging.debug("Receiver wallet not found in database. Treating as external.")
            receiver_user_id = None  # External wallet

        # Log Transaction
        cursor.execute(
            "INSERT INTO transactions (sender_address, receiver_address, amount, currency_type) VALUES (%s, %s, %s, %s)",
            (sender_wallet_address, receiver_address, amount, currency_type)
        )

        conn.commit()
        return jsonify({'success': True, 'message': f'Successfully sent {amount} {currency_type} to {receiver_address}'}), 200

    except Exception as e:
        conn.rollback()
        logging.error(f"Transaction failed: {e}")
        return jsonify({'error': f"Transaction failed: {str(e)}"}), 500

    finally:
        cursor.close()
        conn.close()
@app.route('/transaction_history_page')
def transaction_history_page():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = get_db_connection()
    if not conn:
        flash("Database connection failed", "error")
        return redirect(url_for('dashboard'))

    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT transaction_id, sender_address, receiver_address, amount, currency_type, transaction_timestamp
            FROM transactions
            WHERE sender_address = (SELECT wallet_address FROM wallets WHERE user_id = %s)
            OR receiver_address = (SELECT wallet_address FROM wallets WHERE user_id = %s)
            ORDER BY transaction_timestamp DESC
            """,
            (user_id, user_id)
        )
        transactions = cursor.fetchall()

        # Debugging: Print fetched transactions
        print("Fetched transactions:", transactions)

        transactions_list = [
            {
                'id': tx[0],
                'description': f"Sent {tx[3]} {tx[4]} to {tx[2]}" if tx[1] else f"Received {tx[3]} {tx[4]} from {tx[1]}",
                'date': tx[5].strftime("%Y-%m-%d %H:%M:%S")  # Ensure timestamp formatting
            }
            for tx in transactions
        ]

        # Debugging: Print formatted transactions list
        print("Formatted transactions list:", transactions_list)

        return render_template('transaction_history.html', transactions=transactions_list)

    except Exception as e:
        logging.error(f"Error fetching transactions: {e}")
        flash("Failed to fetch transaction history", "error")
        return redirect(url_for('dashboard'))

    finally:
        cursor.close()
        conn.close()


@app.route('/about')
def about():
    return render_template('aboutus.html')


@app.route('/register', methods=['GET'])
def show_register_form():
    return render_template('login.html')


@app.route('/perform_swap', methods=['POST'])
def perform_swap():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401

    data = request.get_json()
    from_coin = data.get('fromCoin')
    to_coin = data.get('toCoin')
    from_amount = data.get('fromAmount')
    to_amount = data.get('toAmount')  # *Recalculate this server-side in a real app!*

    user_id = session['user_id']

    try:
        from_amount = float(from_amount)
        to_amount = float(to_amount)  # You'd recalculate this properly!
    except ValueError:
        return jsonify({'error': 'Invalid amount format'}), 400


    conn = get_db_connection()
    if not conn:
        return jsonify({'error': "Failed to connect to database."}), 500

    cursor = conn.cursor()

    try:
        # 1. Check From Balance
        cursor.execute("SELECT balance FROM balances WHERE user_id = %s AND currency_type = %s", (user_id, from_coin))
        from_balance_result = cursor.fetchone()

        if not from_balance_result:
            return jsonify({'error': f'Balance not found for {from_coin}'}), 404

        from_balance = float(from_balance_result[0])

        if from_balance < from_amount:
            return jsonify({'error': 'Insufficient balance'}), 400

        # 2. Deduct From Balance
        cursor.execute("UPDATE balances SET balance = balance - %s WHERE user_id = %s AND currency_type = %s",
                       (from_amount, user_id, from_coin))

        # 3. Add To Balance
        cursor.execute("UPDATE balances SET balance = balance + %s WHERE user_id = %s AND currency_type = %s",
                       (to_amount, user_id, to_coin))

        # 4. Record Transaction
        cursor.execute(
            "INSERT INTO transactions (user_id, amount, currency_type, swap_to_currency) VALUES (%s, %s, %s, %s)",
            (user_id, from_amount, from_coin, to_coin)
        )

        conn.commit()
        return jsonify({'success': True, 'message': f'Successfully swapped {from_amount} {from_coin} for {to_amount} {to_coin}'}), 200

    except Exception as e:
        if conn:
            conn.rollback()  # Rollback on error
        logging.error(f"Swap transaction failed: {e}")
        return jsonify({'error': f"Swap transaction failed: {str(e)}"}), 500

    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()



if __name__ == '__main__':
    app.run(debug=True)