import sys
from shopifyapp import app


if __name__ == '__main__':
    port = sys.argv[1] if len(sys.argv) > 1 else 8888
    app.run(host='0.0.0.0', port=port, debug=True)
