from sociallogin import app


if __name__ == '__main__':
    import sys
    port = sys.argv[1] if len(sys.argv) > 1 else 5000
    app.run(host='0.0.0.0', port=port, debug=True)