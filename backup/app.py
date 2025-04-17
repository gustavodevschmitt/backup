from flask import Flask, request, Response, stream_with_context, render_template_string, jsonify
import requests
import logging
from datetime import datetime, timedelta
import secrets
import json
import ipaddress

# ConfiguraÃ§Ã£o do logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Carregar os arquivos JSON
with open('videos.json', 'r') as f:
    videos_data = json.load(f)

with open('series.json', 'r') as f:
    series_data = json.load(f)

# Cache para armazenar a URL final e sua validade
redirect_cache = {
    'url': None,
    'expires': None
}

# Cache para armazenar tokens vÃ¡lidos por IP
token_cache = {}

# Lista para armazenar IPs online e suas atividades
ips_online = []

# Lista para armazenar logs em memÃ³ria
logs = []

def normalize_ip(ip):
    """Normaliza o endereÃ§o IP (IPv4 ou IPv6)."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return str(ip_obj)
    except ValueError:
        return ip

def get_client_ip():
    """ObtÃ©m o IP real do cliente (suporta IPv4 e IPv6)."""
    if 'CF-Connecting-IP' in request.headers:
        return normalize_ip(request.headers['CF-Connecting-IP'])
    if 'X-Forwarded-For' in request.headers:
        return normalize_ip(request.headers['X-Forwarded-For'].split(',')[0].strip())
    return normalize_ip(request.remote_addr)

def is_valid_referer(referer):
    """Verifica se o referer Ã© vÃ¡lido, considerando possÃ­veis variaÃ§Ãµes de URL."""
    if not referer:
        return False
    
    valid_patterns = [
        '/e/',
        '/s/',
        'http://',
        'https://'
    ]
    
    return any(pattern in referer for pattern in valid_patterns)

def get_series_url(tmdb_id, season, episode):
    """ObtÃ©m a URL do episÃ³dio da sÃ©rie."""
    serie = next((s for s in series_data if s['id'] == str(tmdb_id)), None)
    if not serie:
        logger.error(f"SÃ©rie com id {tmdb_id} nÃ£o encontrada.")
        return None

    temporada = next((t for t in serie['temporadas'] if t['temporada'] == season), None)
    if not temporada:
        logger.error(f"Temporada {season} nÃ£o encontrada para sÃ©rie {tmdb_id}.")
        return None

    episodio_url = temporada['episodios'].get(str(episode))
    if not episodio_url:
        logger.error(f"EpisÃ³dio {episode} nÃ£o encontrado na temporada {season} da sÃ©rie {tmdb_id}.")
        return None

    return episodio_url

def get_final_url(tmdb_id, season=None, episode=None):
    """ObtÃ©m a URL final apÃ³s redirecionamento."""
    global redirect_cache

    if season is not None and episode is not None:
        REAL_URL = get_series_url(tmdb_id, season, episode)
    else:
        video_info = next((video for video in videos_data if video['id'] == tmdb_id), None)
        if not video_info:
            logger.error(f"VÃ­deo com id {tmdb_id} nÃ£o encontrado.")
            return None
        REAL_URL = video_info['url']

    if not REAL_URL:
        return None

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Referer': 'https://sv1.casahd.com'
    }

    try:
        initial_req = requests.get(REAL_URL, headers=headers, allow_redirects=False, timeout=10)
    except requests.exceptions.RequestException as e:
        logger.error(f"Erro ao acessar a URL real: {e}")
        return None

    if initial_req.status_code in (301, 302, 303, 307, 308):
        redirect_url = initial_req.headers['Location']
        redirect_cache['url'] = redirect_url
        redirect_cache['expires'] = datetime.now() + timedelta(hours=1)
        return redirect_url
    else:
        logger.error("Nenhum redirecionamento detectado.")
        return None

def clean_token(client_ip):
    """Remove o token do cache para o IP fornecido."""
    if client_ip in token_cache:
        del token_cache[client_ip]
        logger.info(f"Token removido para IP: {client_ip}")
        logs.append(f"{datetime.now()} - Token removido para IP: {client_ip}")

def renew_token(client_ip):
    """Renova o token para o IP fornecido."""
    new_token = secrets.token_urlsafe(16)
    token_cache[client_ip] = {
        'token': new_token,
        'expires': datetime.now() + timedelta(hours=1)
    }
    logger.info(f"Token renovado para o IP {client_ip}")
    logs.append(f"{datetime.now()} - Token renovado para o IP: {client_ip}")
    return new_token

@app.route('/s/<int:tmdb_id>/<int:season>/<int:episode>')
def stream_series(tmdb_id, season, episode):
    client_ip = get_client_ip()
    logger.info(f"Novo acesso ao player de sÃ©rie. IP: {client_ip}")

    clean_token(client_ip)
    ips_online[:] = [entry for entry in ips_online if entry['ip'] != client_ip]
    ips_online.append({'ip': client_ip, 'last_activity': datetime.now()})

    token = secrets.token_urlsafe(16)
    token_cache[client_ip] = {
        'token': token,
        'expires': datetime.now() + timedelta(hours=1)
    }
    
    logs.append(f"{datetime.now()} - Novo acesso ao player de sÃ©rie. IP: {client_ip}")

    return render_template_string('''
        <!DOCTYPE html>
        <html lang="pt-br">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>SPACEFLIX</title>
            <script src="/jwplayer-lib"></script>
            <style>
                body {
                    margin: 0;
                    padding: 0;
                    background-color: #000;
                    width: 100vw;
                    height: 100vh;
                    overflow: hidden;
                }

                #player-container {
                    position: absolute;
                    top: 0;
                    left: 0;
                    width: 100%;
                    height: 100%;
                }

                #player {
                    position: absolute;
                    top: 0;
                    left: 0;
                    width: 100% !important;
                    height: 100% !important;
                }

                .watermark {
                    position: fixed;
                    top: 20px;
                    right: 20px;
                    z-index: 9999;
                    pointer-events: none;
                    opacity: 0.5;
                    transition: opacity 0.3s ease;
                    width: 150px;
                    height: auto;
                }

                .watermark img {
                    width: 100%;
                    height: auto;
                    filter: drop-shadow(2px 2px 2px rgba(0, 0, 0, 0.5));
                }

                .watermark:hover {
                    opacity: 0.7;
                }

                .episode-info {
                    position: fixed;
                    top: 10px;
                    left: 10px;
                    color: red;
                    font-size: 16px;
                    font-weight: bold;
                    font-family: Arial, sans-serif;
                    z-index: 9999;
                    pointer-events: none;
                    text-shadow: 1px 1px 2px #000;
                    opacity: 0.4;
                }

                .jw-wrapper {
                    position: absolute !important;
                    top: 0 !important;
                    left: 0 !important;
                    width: 100% !important;
                    height: 100% !important;
                }

                .jw-aspect {
                    display: none !important;
                }

                .jw-media {
                    object-fit: cover !important;
                }

                .jw-icon-cast {
                    display: flex !important;
                    visibility: visible !important;
                    opacity: 1 !important;
                }

                .jw-icon-cast button {
                    color: #ff0000 !important;
                }

                .jw-button-color {
                    color: #ff0000 !important;
                }

                .jw-text {
                    color: #ff0000 !important;
                }

                /* Novos estilos para a barra de progresso */
                .jw-slider-time .jw-slider-container {
                    height: 4px !important;
                }

                .jw-progress {
                    background: linear-gradient(to right, #ff0000, #ff4d4d) !important;
                }

                .jw-rail {
                    background-color: rgba(255, 255, 255, 0.2) !important;
                }

                .jw-buffer {
                    background-color: rgba(255, 255, 255, 0.3) !important;
                }

                .jw-knob {
                    background-color: #fff !important;
                    border-radius: 50% !important;
                    width: 12px !important;
                    height: 12px !important;
                    margin-top: -4px !important;
                }
            </style>
        </head>
        <body>
            <div id="player-container">
                <div class="watermark">
                    <img src="https://spaceflix.online/static/img/logo-1743997691.png" alt="SPACEFLIX">
                </div>
                <div class="episode-info">T{{ season }}:E{{ episode }}</div>
                <div id="player"></div>
            </div>

            <script>
                const player = jwplayer("player").setup({
                    file: decodeURIComponent("{{ url_for('video_stream', token=token, tmdb_id=tmdb_id, season=season, episode=episode)|safe }}"),
                    type: "mp4",
                    autostart: false,
                    controls: true,
                    width: "100%",
                    height: "100%",
                    stretching: "fill",
                    mute: false,
                    volume: 75,
                    cast: {},
                    skin: {
                        name: "glow",
                        active: "#ff0000",
                        inactive: "#ff4d4d",
                        background: "#000000"
                    }
                });

                const checkCastButton = setInterval(() => {
                    const castIcon = document.querySelector(".jw-icon-cast");
                    if (castIcon) {
                        castIcon.style.display = "flex";
                        castIcon.style.visibility = "visible";
                        castIcon.style.opacity = "1";
                        clearInterval(checkCastButton);
                    }
                }, 1000);

                // Detectar quando o vÃ­deo termina
                player.on('complete', function() {
                    fetch('/end_session', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({
                            token: '{{ token }}'
                        })
                    });
                });
            </script>
        </body>
        </html>
    ''', token=token, tmdb_id=tmdb_id, season=season, episode=episode)

@app.route('/e/<int:tmdb_id>')
def stream(tmdb_id):
    client_ip = get_client_ip()
    logger.info(f"Novo acesso ao player de filme. IP: {client_ip}")

    clean_token(client_ip)
    ips_online[:] = [entry for entry in ips_online if entry['ip'] != client_ip]
    ips_online.append({'ip': client_ip, 'last_activity': datetime.now()})

    token = secrets.token_urlsafe(16)
    token_cache[client_ip] = {
        'token': token,
        'expires': datetime.now() + timedelta(hours=1)
    }
    
    logs.append(f"{datetime.now()} - Novo acesso ao player de filme. IP: {client_ip}")

    return render_template_string('''
        <!DOCTYPE html>
        <html lang="pt-br">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>SPACEFLIX</title>
            <script src="/jwplayer-lib"></script>
            <style>
                body {
                    margin: 0;
                    padding: 0;
                    background-color: #000;
                    width: 100vw;
                    height: 100vh;
                    overflow: hidden;
                }

                #player-container {
                    position: absolute;
                    top: 0;
                    left: 0;
                    width: 100%;
                    height: 100%;
                }

                #player {
                    position: absolute;
                    top: 0;
                    left: 0;
                    width: 100% !important;
                    height: 100% !important;
                }

                .watermark {
                    position: fixed;
                    top: 20px;
                    right: 20px;
                    z-index: 9999;
                    pointer-events: none;
                    opacity: 0.5;
                    transition: opacity 0.3s ease;
                    width: 150px;
                    height: auto;
                }

                .watermark img {
                    width: 100%;
                    height: auto;
                    filter: drop-shadow(2px 2px 2px rgba(0, 0, 0, 0.5));
                }

                .watermark:hover {
                    opacity: 0.7;
                }

                .jw-wrapper {
                    position: absolute !important;
                    top: 0 !important;
                    left: 0 !important;
                    width: 100% !important;
                    height: 100% !important;
                }

                .jw-aspect {
                    display: none !important;
                }

                .jw-media {
                    object-fit: cover !important;
                }

                .jw-icon-cast {
                    display: flex !important;
                    visibility: visible !important;
                    opacity: 1 !important;
                }

                .jw-icon-cast button {
                    color: #ff0000 !important;
                }

                .jw-button-color {
                    color: #ff0000 !important;
                }

                .jw-text {
                    color: #ff0000 !important;
                }

                /* Novos estilos para a barra de progresso */
                .jw-slider-time .jw-slider-container {
                    height: 4px !important;
                }

                .jw-progress {
                    background: linear-gradient(to right, #ff0000, #ff4d4d) !important;
                }

                .jw-rail {
                    background-color: rgba(255, 255, 255, 0.2) !important;
                }

                .jw-buffer {
                    background-color: rgba(255, 255, 255, 0.3) !important;
                }

                .jw-knob {
                    background-color: #fff !important;
                    border-radius: 50% !important;
                    width: 12px !important;
                    height: 12px !important;
                    margin-top: -4px !important;
                }
            </style>
        </head>
        <body>
            <div id="player-container">
                <div class="watermark">
                    <img src="https://spaceflix.online/static/img/logo-1743997691.png" alt="SPACEFLIX">
                </div>
                <div id="player"></div>
            </div>

            <script>
                const player = jwplayer("player").setup({
                    file: decodeURIComponent("{{ url_for('video_stream', token=token, tmdb_id=tmdb_id)|safe }}"),
                    type: "mp4",
                    autostart: false,
                    controls: true,
                    width: "100%",
                    height: "100%",
                    stretching: "fill",
                    mute: false,
                    volume: 75,
                    cast: {},
                    skin: {
                        name: "glow",
                        active: "#ff0000",
                        inactive: "#ff4d4d",
                        background: "#000000"
                    }
                });

                const checkCastButton = setInterval(() => {
                    const castIcon = document.querySelector(".jw-icon-cast");
                    if (castIcon) {
                        castIcon.style.display = "flex";
                        castIcon.style.visibility = "visible";
                        castIcon.style.opacity = "1";
                        clearInterval(checkCastButton);
                    }
                }, 1000);

                // Detectar quando o vÃ­deo termina
                player.on('complete', function() {
                    fetch('/end_session', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({
                            token: '{{ token }}'
                        })
                    });
                });
            </script>
        </body>
        </html>
    ''', token=token, tmdb_id=tmdb_id)

@app.route('/video')
def video_stream():
    client_ip = get_client_ip()
    logger.info(f"RequisiÃ§Ã£o de vÃ­deo recebida. IP: {client_ip}")

    # Decodifica os parÃ¢metros da URL corretamente
    token = request.args.get('token', '').replace('&amp;', '&')
    tmdb_id = request.args.get('tmdb_id', '').replace('&amp;', '&')
    season = request.args.get('season', '').replace('&amp;', '&')
    episode = request.args.get('episode', '').replace('&amp;', '&')

    if not tmdb_id:
        logger.error(f"tmdb_id nÃ£o fornecido. IP: {client_ip}")
        return "tmdb_id nÃ£o fornecido.", 400
    try:
        tmdb_id = int(tmdb_id)
    except ValueError:
        logger.error(f"tmdb_id invÃ¡lido. IP: {client_ip}")
        return "tmdb_id invÃ¡lido.", 400

    if not token or client_ip not in token_cache or token_cache[client_ip]['token'] != token:
        logger.warning(f"Acesso negado. Token invÃ¡lido para IP: {client_ip}")
        logs.append(f"{datetime.now()} - Acesso negado. Token invÃ¡lido para IP: {client_ip}")
        return "Acesso negado.", 403

    if token_cache[client_ip]['expires'] < datetime.now():
        token = renew_token(client_ip)

    referer = request.headers.get('Referer', '')
    if not is_valid_referer(referer):
        logger.warning(f"Aviso: Referer possivelmente invÃ¡lido para IP: {client_ip} - {referer}")
        # Continua a execuÃ§Ã£o mesmo com referer invÃ¡lido

    try:
        if season and episode:
            final_url = get_final_url(tmdb_id, int(season), int(episode))
        else:
            final_url = get_final_url(tmdb_id)

        if not final_url:
            logger.error("Erro: URL nÃ£o encontrada.")
            logs.append(f"{datetime.now()} - Erro: URL nÃ£o encontrada para o IP: {client_ip}")
            return "Erro ao acessar o vÃ­deo.", 500

        range_header = request.headers.get('Range')
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Referer': 'https://zed3.top/'
        }
        if range_header:
            headers['Range'] = range_header
            logger.info(f"RequisiÃ§Ã£o com Range: {range_header}")

        final_req = requests.get(final_url, headers=headers, stream=True, timeout=10)
        final_req.raise_for_status()

        response_headers = {
            'Content-Type': final_req.headers.get('Content-Type', 'video/mp4'),
            'Content-Length': final_req.headers.get('Content-Length', ''),
            'Accept-Ranges': 'bytes',
            'Content-Range': final_req.headers.get('Content-Range', '')
        }

        for entry in ips_online:
            if entry['ip'] == client_ip:
                entry['last_activity'] = datetime.now()

        clean_inactive_sessions()

        logger.info(f"Retransmitindo vÃ­deo para o IP: {client_ip}")
        logs.append(f"{datetime.now()} - Retransmitindo vÃ­deo para o IP: {client_ip}")
        return Response(
            stream_with_context(final_req.iter_content(chunk_size=1024 * 1024)),
            headers=response_headers,
            status=206 if range_header else 200
        )

    except requests.exceptions.RequestException as e:
        logger.error(f"Erro na requisiÃ§Ã£o Ã  URL real: {e}")
        logs.append(f"{datetime.now()} - Erro na requisiÃ§Ã£o Ã  URL real: {e} para o IP: {client_ip}")
        return "Erro ao acessar o vÃ­deo.", 500
    except Exception as e:
        logger.error(f"Erro inesperado: {e}")
        logs.append(f"{datetime.now()} - Erro inesperado: {e} para o IP: {client_ip}")
        return "Erro inesperado.", 500

def clean_inactive_sessions():
    """Limpa sessÃµes inativas."""
    global ips_online, token_cache

    current_time = datetime.now()
    inactive_ips = [entry['ip'] for entry in ips_online if current_time - entry['last_activity'] > timedelta(hours=1)]

    for ip in inactive_ips:
        ips_online = [entry for entry in ips_online if entry['ip'] != ip]
        if ip in token_cache:
            del token_cache[ip]
        logger.info(f"Limpeza de sessÃ£o inativa. IP: {ip}")
        logs.append(f"{datetime.now()} - Limpeza de sessÃ£o inativa. IP: {ip}")

@app.route('/end_session', methods=['POST'])
def end_session():
    """Encerra a sessÃ£o do usuÃ¡rio."""
    client_ip = get_client_ip()
    logger.info(f"Encerrando sessÃ£o para IP: {client_ip}")

    clean_token(client_ip)
    ips_online[:] = [entry for entry in ips_online if entry['ip'] != client_ip]
    
    logs.append(f"{datetime.now()} - SessÃ£o encerrada para IP: {client_ip}")
    return jsonify({"message": "SessÃ£o encerrada com sucesso."}), 200

@app.route('/logs')
def logs_view():
    """VisualizaÃ§Ã£o de logs e IPs online."""
    auth = request.authorization
    if not auth or auth.username != 'admin' or auth.password != '9agos2010':
        return Response('Acesso negado.', 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})

    logs_html = '''
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Logs - SPACEFLIX</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    background-color: #121212;
                    color: #e0e0e0;
                    margin: 0;
                    padding: 20px;
                }
                .container {
                    max-width: 1200px;
                    margin: auto;
                    background: #1e1e1e;
                    padding: 20px;
                    box-shadow: 0 0 10px rgba(0, 0, 0, 0.5);
                    border-radius: 8px;
                }
                h1 {
                    text-align: center;
                    color: #bb86fc;
                    margin-bottom: 20px;
                }
                .table-container {
                    display: flex;
                    justify-content: space-between;
                    margin-top: 20px;
                    gap: 20px;
                }
                table {
                    width: 48%;
                    border-collapse: collapse;
                    background-color: #2d2d2d;
                    border-radius: 8px;
                    overflow: hidden;
                }
                table, th, td {
                    border: 1px solid #3e3e3e;
                }
                th, td {
                    padding: 12px;
                    text-align: left;
                }
                th {
                    background-color: #3e3e3e;
                    color: #bb86fc;
                }
                tr:nth-child(even) {
                    background-color: #2a2a2a;
                }
                .logs {
                    background-color: #2d2d2d;
                    border-radius: 8px;
                    padding: 10px;
                    white-space: pre-wrap;
                    max-height: 400px;
                    overflow-y: auto;
                }
                .logs::-webkit-scrollbar {
                    width: 8px;
                }
                .logs::-webkit-scrollbar-thumb {
                    background-color: #bb86fc;
                    border-radius: 8px;
                }
                .logs::-webkit-scrollbar-track {
                    background: #2d2d2d;
                }
                .highlight {
                    color: #03dac6;
                }
                @keyframes fadeIn {
                    from { opacity: 0; }
                    to { opacity: 1; }
                }
                .container {
                    animation: fadeIn 1s ease-in-out;
                }
                .logs {
                    animation: fadeIn 2s ease-in-out;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>SPACEFLIX - Video Streaming Server</h1>
                <div class="table-container">
                    <div>
                        <h2>IPs Online</h2>
                        <table>
                            <tr>
                                <th>IP</th>
                                <th>Ãšltima Atividade</th>
                            </tr>
                            {% for ip in ips_online %}
                            <tr>
                                <td>{{ ip.ip }}</td>
                                <td>{{ ip.last_activity }}</td>
                            </tr>
                            {% endfor %}
                        </table>
                    </div>
                    <div>
                        <h2>Logs</h2>
                        <div class="logs">{{ logs }}</div>
                    </div>
                </div>
            </div>
        </body>
        </html>
    '''

    return render_template_string(logs_html, ips_online=ips_online, logs="\n".join(logs))

@app.route('/jwplayer-lib')
def serve_jwplayer():
    client_ip = get_client_ip()
    referer = request.headers.get('Referer', '')
    
    # Verifica se o token é válido
    if client_ip not in token_cache:
        return "Acesso negado", 403
        
    if not is_valid_referer(referer):
        return "Acesso negado", 403
    
    # URL do script do JW Player com a chave
    jw_script = requests.get('https://cdn.jwplayer.com/libraries/0jpQcr3p.js')
    
    response = Response(jw_script.content, content_type='application/javascript')
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    return response

if __name__ == '__main__':
    logger.info("Iniciando o servidor Flask na porta 80")
    app.run(host='0.0.0.0', port=5000, debug=True)
