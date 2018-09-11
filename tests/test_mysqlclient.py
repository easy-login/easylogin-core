import MySQLdb
from datetime import datetime, timedelta
import random
import secrets
import json


def get_total_auth_report(db, app_id):
    cursor = db.cursor()
    cursor.execute("""
        SELECT is_login, count(id) 
        FROM auth_logs 
        WHERE app_id = %s and status = 'succeeded' 
        GROUP BY is_login""", (app_id,))
    rows = cursor.fetchmany(2)
    return [(int(row[0]), int(row[1])) if row else (None, None) for row in rows]


def get_auth_report_per_provider(db, app_id, from_dt=None, to_dt=None, is_login=1):
    cursor = db.cursor()
    _from = datetime.strptime(from_dt, '%Y-%m-%d')
    _to = datetime.strptime(to_dt, '%Y-%m-%d')

    results = dict()
    for provider in ['line', 'yahoojp', 'amazon', 'total']:
        results[provider] = {}

    while _from <= _to:
        dt_str = _from.strftime('%Y-%m-%d')
        for provider in ['line', 'yahoojp', 'amazon', 'total']:
            results[provider][dt_str] = 0
        _from += timedelta(days=1)

    from_dt += ' 00:00:00'
    to_dt += ' 23:59:59'
    cursor.execute("""
        SELECT provider, DATE(modified_at), COUNT(provider) 
        FROM auth_logs 
        WHERE app_id = %s AND modified_at BETWEEN %s and %s AND status = 'succeeded' AND is_login = %s
        GROUP BY DATE(modified_at), provider""", (app_id, from_dt, to_dt, is_login))

    i = 0
    while True:
        rows = cursor.fetchmany(500)
        if not rows:
            break
        for row in rows:
            i += 1
            dt_str = row[1].strftime('%Y-%m-%d')
            provider = row[0]
            results[provider][dt_str] = int(row[2])
            results['total'][dt_str] += int(row[2])

    return results


def insert_sample_data(db):
    providers = ['line', 'amazon', 'yahoojp']
    samples = []
    for i in range(0, 100):
        provider = random.choice(providers)
        dt = datetime.now() - timedelta(random.randint(0, 10))
        nonce = secrets.token_hex(16)
        samples.append((
            dt, dt,
            provider,
            'http://localhost:8080/auth/callback',
            nonce,
            'succeeded',
            3, random.randint(0, 1)
        ))

    db.cursor().executemany(
        """
        INSERT INTO auth_logs (created_at, modified_at, provider, callback_uri, nonce, status, app_id, is_login)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""", samples)
    db.commit()


if __name__ == '__main__':
    db = MySQLdb.connect(host='192.168.9.89', user='guest', passwd='123456', db='nhatanhdb')
    # insert_sample_data(db)
    # res = get_auth_report_per_provider(db, app_id=3, from_dt='2018-08-29', to_dt='2018-09-4', is_login=0)
    res = get_total_auth_report(db, app_id=3)
    print(res)
