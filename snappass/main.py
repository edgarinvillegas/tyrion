import os
import re
import sys
import uuid
import datetime
import json
import smtplib
import threading
from email.mime.text import MIMEText

import redis

from cryptography.fernet import Fernet
from flask import abort, Flask, render_template, request
from redis.exceptions import ConnectionError
from werkzeug.urls import url_quote_plus
from werkzeug.urls import url_unquote_plus

NO_SSL = os.environ.get('NO_SSL', False)
TOKEN_SEPARATOR = '~'


# Initialize Flask Application
app = Flask(__name__)
if os.environ.get('DEBUG'):
    app.debug = True
app.secret_key = os.environ.get('SECRET_KEY', 'Secret Key')
app.config.update(
    dict(STATIC_URL=os.environ.get('STATIC_URL', 'static')))

# Initialize Redis
if os.environ.get('MOCK_REDIS'):
    from mockredis import mock_strict_redis_client
    redis_client = mock_strict_redis_client()
elif os.environ.get('REDIS_URL'):
    redis_client = redis.StrictRedis.from_url(os.environ.get('REDIS_URL'))
else:
    redis_host = os.environ.get('REDIS_HOST', 'localhost')
    redis_port = os.environ.get('REDIS_PORT', 6379)
    redis_db = os.environ.get('SNAPPASS_REDIS_DB', 0)
    redis_client = redis.StrictRedis(
        host=redis_host, port=redis_port, db=redis_db)
REDIS_PREFIX = os.environ.get('REDIS_PREFIX', 'tyrion-')

TIME_CONVERSION = {'sixmonths': 16070400, 'quarter': 8035200, 'month': 2592000, 'week': 604800, 'day': 86400, 'hour': 3600}
TIME_LABELS = {'sixmonths': 'Six months', 'quarter': 'Quarter', 'month': 'Month', 'week': 'Week', 'day': 'Day', 'hour': 'Hour'}

gmail_email = os.environ.get('SNAPPASS_EMAIL', '')
gmail_password = os.environ.get('SNAPPASS_EMAIL_PASSWORD', '')

#Based on https://stackoverflow.com/questions/4447081/how-to-send-asynchronous-email-using-django
class EmailThread(threading.Thread):
    def __init__(self, subject, raw_to, body):
        self.subject = subject
        self.raw_to = raw_to
        self.body = body
        threading.Thread.__init__(self)

    def run (self):
        send_mail(self.subject, self.raw_to, self.body)

def async_send_mail(subject, raw_to, body):
    print('send_mail commented out')
    EmailThread(subject, raw_to, body).start()

def send_mail(subject, raw_to, body):
    if not gmail_email or not gmail_password:
        return

    sent_from = gmail_email
    # Create a text/plain message
    msg = MIMEText(body, 'plain', 'utf-8')
    msg['Subject'] = subject
    msg['From'] = sent_from
    to = [x.strip() for x in raw_to.split(',')]     #Split by comma and trim
    msg['To'] = ', '.join(to)

    try:
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.ehlo()
        server.login(gmail_email, gmail_password)
        server.sendmail(sent_from, to, msg.as_string())
        server.close()
        print('Email sent to ' + raw_to)
        return True
    except:
        print('Error: email not sent to ' + raw_to)
        return False

def check_redis_alive(fn):
    def inner(*args, **kwargs):
        try:
            if fn.__name__ == 'main':
                redis_client.ping()
            return fn(*args, **kwargs)
        except ConnectionError as e:
            print('Failed to connect to redis! %s' % e.message)
            if fn.__name__ == 'main':
                sys.exit(0)
            else:
                return abort(500)
    return inner


def encrypt(password):
    """
    Take a password string, encrypt it with Fernet symmetric encryption,
    and return the result (bytes), with the decryption key (bytes)
    """
    encryption_key = Fernet.generate_key()
    fernet = Fernet(encryption_key)
    encrypted_password = fernet.encrypt(password.encode('utf-8'))
    return encrypted_password, encryption_key


def decrypt(password, decryption_key):
    """
    Decrypt a password (bytes) using the provided key (bytes),
    and return the plain-text password (bytes).
    """
    fernet = Fernet(decryption_key)
    return fernet.decrypt(password)


def parse_token(token):
    token_fragments = token.split(TOKEN_SEPARATOR, 1)  # Split once, not more.
    storage_key = token_fragments[0]

    try:
        decryption_key = token_fragments[1].encode('utf-8')
    except IndexError:
        decryption_key = None

    return storage_key, decryption_key


@check_redis_alive
def set_password(password, ttl):
    """
    Encrypt and store the password for the specified lifetime.

    Returns a token comprised of the key where the encrypted password
    is stored, and the decryption key.
    """
    storage_key = REDIS_PREFIX + uuid.uuid4().hex
    encrypted_password, encryption_key = encrypt(password)
    redis_client.setex(storage_key, ttl, encrypted_password)
    encryption_key = encryption_key.decode('utf-8')
    token = TOKEN_SEPARATOR.join([storage_key, encryption_key])
    return token

def get_revealed_email_body(contentObj):
    # return contentObj['message']
    timestamp = contentObj['timestamp'].replace('T', ' ')
    message = contentObj['message']
    revealerMessage = get_revealer_message()
    body = u'Someone saw your secret set on {} (server time). '.format(timestamp)
    if message:
        body = body + u'\n---Context info:---\n{}'.format(message)
    if revealerMessage:
        body = body + u'\n---Message sent by revealer:---\n{}'.format(revealerMessage)
    return body

def get_expiry_date_formatted(time_period):
    ttl = TIME_CONVERSION[time_period]
    if ttl <= 86400:
        return TIME_LABELS[time_period]
    else:
        return (datetime.datetime.now() + datetime.timedelta(seconds=ttl)).strftime('%Y-%m-%d')


def get_secret_set_email_body(contentObj, time_period):
    # return contentObj['message']
    timestamp = contentObj['timestamp'].replace('T', ' ')
    message = contentObj['message']
    expiration = get_expiry_date_formatted(time_period)

    body = u'You set a secret on {} (server time). '.format(timestamp)
    body = body + u'\nExpiration: {}'.format(expiration)
    if message:
        body = body + u'\nContext info:\n{}'.format(message)
    return body

@check_redis_alive
def get_password(token):
    """
    From a given token, return the initial password.

    If the token is tilde-separated, we decrypt the password fetched from Redis.
    If not, the password is simply returned as is.
    """
    storage_key, decryption_key = parse_token(token)
    password = redis_client.get(storage_key)
    redis_client.delete(storage_key)

    if password is not None:

        if decryption_key is not None:
            password = decrypt(password, decryption_key)

        contentStr = password.decode('utf-8')
        contentObj = json.loads(contentStr)
        email = contentObj['email'].strip()
        if email:
            async_send_mail('Someone saw your secret', email, get_revealed_email_body(contentObj))
        return contentStr

@check_redis_alive
def password_exists(token):
    storage_key, decryption_key = parse_token(token)
    return redis_client.exists(storage_key)

def empty(value):
    if not value:
        return True


def clean_input():
    """
    Make sure we're not getting bad data from the front end,
    format data to be machine readable
    """
    if empty(request.form.get('password', '')):
        abort(400)

    if empty(request.form.get('ttl', '')):
        abort(400)

    time_period = request.form['ttl'].lower()
    if time_period not in TIME_CONVERSION:
        abort(400)

    #return TIME_CONVERSION[time_period], request.form['password']
    return time_period, request.form['password'], request.form['email'], request.form['message']

def get_revealer_message():
    if request.form.get('sendRevealerMessage', '') == 'on':
        return request.form.get('revealerMessage', '').strip()
    return ''

@app.route('/', methods=['GET'])
def index():
    return render_template('set_password.html')


@app.route('/', methods=['POST'])
def handle_password():
    # ttl, password = clean_input() #edgarin
    time_period, password, email, message = clean_input()
    ttl = TIME_CONVERSION[time_period]
    timestamp = datetime.datetime.now().replace(microsecond=0).isoformat()
    contentObj = {'password': password, 'email': email, 'message': message, 'timestamp': timestamp} #edgarin
    expiration = get_expiry_date_formatted(time_period)

    # print(json.dumps(contentObj))
    token = set_password( json.dumps(contentObj), ttl)

    if NO_SSL:
        base_url = request.url_root
    else:
        base_url = request.url_root.replace("http://", "https://")
    link = base_url + url_quote_plus(token)
    async_send_mail('You set a secret', contentObj['email'], get_secret_set_email_body(contentObj, time_period))

    return render_template('confirm.html', password_link=link, timestamp=timestamp.replace('T', ' '), expiration=expiration)


@app.route('/<password_key>', methods=['GET'])
def preview_password(password_key):
    password_key = url_unquote_plus(password_key)
    if not password_exists(password_key):
        abort(404)

    return render_template('preview.html')


@app.route('/<password_key>', methods=['POST'])
def show_password(password_key):
    password_key = url_unquote_plus(password_key)
    contentStr = get_password(password_key)
    if not contentStr:
        abort(404)
    contentObj = json.loads(contentStr)
    password = contentObj['password']
    console_log = 'Email sent from ' + gmail_email + ' to ' + contentObj['email']
    return render_template('password.html', password=password, log=console_log)


@check_redis_alive
def main():
    app.run(host='0.0.0.0', port=5002)

if __name__ == '__main__':
    main()

