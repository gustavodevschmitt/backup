from flask import Flask, jsonify, request, Response, render_template
from flask_cors import CORS
import jwt
import time
import requests
import os
import hashlib
import json
from functools import wraps
from urllib.parse import urljoin, urlparse

app = Flask(__name__)

# Lista de domínios permitidos
ALLOWED_DOMAINS = [
    'alphaembeder.com.br',
    'embed.alphaembeder.com.br',
    'spaceflix.online',    
    '127.0.0.1'
]

# Configuração do CORS para permitir apenas os domínios específicos
CORS(app, resources={
    r"/*": {
        "origins": "*",  # Permitir todos os origins já que a Cloudflare vai gerenciar isso
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization", "CF-Connecting-IP", "CF-IPCountry", "CF-RAY", "X-Forwarded-For"]
    }
})

# Configurações
SECRET_KEY = os.environ.get('SECRET_KEY', '9agos2010')

# Carrega os canais do arquivo de configuração
def load_channels():
    try:
        config_path = os.path.join(os.path.dirname(__file__), 'config', 'channels.json')
        with open(config_path, 'r') as f:
            channels = json.load(f)
            
        # Remove as URLs dos canais da memória do servidor
        channels_public = {}
        for channel_id, data in channels.items():
            channels_public[channel_id] = {
                'name': data['name'],
                'key': data['key']
            }
            
        return channels, channels_public
    except Exception as e:
        print(f"Erro ao carregar canais: {e}")
        return {}, {}

# Carrega os canais uma única vez na inicialização
CHANNELS, CHANNELS_PUBLIC = load_channels()

def is_allowed_domain(referer):
    """Verifica se o domínio está na lista de permitidos"""
    print("\n=== Verificação de Domínio ===")
    print(f"Headers completos: {dict(request.headers)}")
    print(f"Referer: {referer}")
    
    # Se não tiver referer, verifica se é uma requisição XHR
    if not referer:
        is_xhr = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        print(f"Sem referer, é XHR? {is_xhr}")
        return is_xhr
    
    try:
        parsed = urlparse(referer)
        referer_domain = parsed.netloc.split(':')[0]  # Remove a porta se existir
        print(f"Domínio extraído: {referer_domain}")
        
        # Verifica se o domínio ou qualquer subdomínio está permitido
        is_allowed = any(
            referer_domain == domain or referer_domain.endswith('.' + domain)
            for domain in ALLOWED_DOMAINS
        )
        print(f"Domínio permitido? {is_allowed}")
        return is_allowed
        
    except Exception as e:
        print(f"Erro ao verificar referer: {e}")
        return False

def check_referer():
    """Verifica se a requisição veio do nosso player"""
    referer = request.headers.get('Referer', '')
    origin = request.headers.get('Origin', '')
    
    print("\n=== Verificação de Referer ===")
    print(f"Referer: {referer}")
    print(f"Origin: {origin}")
    print(f"X-Requested-With: {request.headers.get('X-Requested-With')}")
    
    # Se for para um arquivo .ts ou um segmento, verificação mais relaxada para o referer
    segment = request.args.get('segment', '')
    if segment and (segment.endswith('.ts') or 'mono.ts' in segment):
        # Para segmentos de vídeo, verificamos apenas se o domínio é permitido
        return is_allowed_domain(referer or origin)
    
    # Se for uma requisição XHR, verifica o domínio
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return is_allowed_domain(referer or origin)
    
    # Se não for XHR, verifica se é uma requisição normal do domínio permitido
    return is_allowed_domain(referer)

def generate_stream_key():
    """Gera uma chave única para o stream"""
    timestamp = str(int(time.time()))
    unique_id = hashlib.sha256(f"{timestamp}{SECRET_KEY}".encode()).hexdigest()
    return unique_id[:32]

def gerar_token(stream_key, channel_id):
    """Gera um token JWT válido por 3 horas"""
    if channel_id not in CHANNELS:
        raise ValueError("Canal inválido")
        
    payload = {
        'exp': time.time() + 10800,  # 3 horas (3600 * 3)
        'iat': time.time(),
        'sub': 'stream_access',
        'stream_key': stream_key,
        'channel': channel_id,
        'channel_key': CHANNELS[channel_id]['key']
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def requer_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not check_referer():
            return jsonify({'mensagem': 'achou que era mais esperto kkkkk'}), 403
            
        token = request.args.get('token')
        if not token:
            return jsonify({'mensagem': 'achou que era mais esperto kkkkk'}), 403
        
        # Verificar se é um segmento .ts ou mono.ts
        segment = request.args.get('segment', '')
        is_video_segment = segment and (segment.endswith('.ts') or 'mono.ts' in segment)
            
        try:
            # Para segmentos de vídeo, podemos ser mais tolerantes com a expiração do token
            verify_options = {}
            if is_video_segment:
                # Para segmentos, não verificamos expiração do token
                verify_options = {'verify_exp': False}
                
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'], options=verify_options)
            
            # Se é um segmento e o token expirou, verificamos se expirou há menos de 1 hora
            if is_video_segment and 'exp' in payload and payload['exp'] < time.time():
                # Se expirou há mais de 1 hora, rejeitamos
                if payload['exp'] < time.time() - 3600:
                    raise jwt.InvalidTokenError()
            
            request.stream_key = payload.get('stream_key')
            request.channel_key = payload.get('channel_key')
            request.channel = payload.get('channel')
            
            # Validação adicional do canal
            if (request.channel not in CHANNELS or 
                CHANNELS[request.channel]['key'] != request.channel_key):
                raise jwt.InvalidTokenError()
                
        except:
            return jsonify({'mensagem': 'achou que era mais esperto kkkkk'}), 403
        return f(*args, **kwargs)
    return decorated

@app.route('/token/<channel_id>')
def obter_token(channel_id):
    """Endpoint para obter um novo token"""
    print(f"\n=== Tentativa de obter token para canal {channel_id} ===")
    
    if not check_referer():
        print("Referer check falhou - Acesso não permitido")
        return jsonify({'mensagem': 'achou que era mais esperto kkkkk'}), 403
        
    if channel_id not in CHANNELS:
        print(f"Canal {channel_id} não encontrado")
        return jsonify({'erro': 'Canal não encontrado'}), 404
        
    stream_key = generate_stream_key()
    token = gerar_token(stream_key, channel_id)
    print(f"Token gerado com sucesso para {channel_id}")
    return jsonify({
        'token': token,
        'stream_key': stream_key
    })

def modify_m3u8_content(content, token, stream_key, channel_id):
    """Modifica o conteúdo do m3u8 para apontar para nosso servidor"""
    lines = content.split('\n')
    modified_lines = []
    
    for line in lines:
        if line.startswith('#'):
            modified_lines.append(line)
        elif line.strip():
            if '.m3u8' in line or '.ts' in line:
                modified_lines.append(f'/stream/{channel_id}?segment={line}&token={token}&key={stream_key}')
            else:
                modified_lines.append(line)
        else:
            modified_lines.append(line)
    
    return '\n'.join(modified_lines)

@app.route('/stream/<channel_id>')
@requer_token
def proxy_stream(channel_id):
    """Proxy para o stream HLS protegido por token"""
    try:
        if channel_id not in CHANNELS:
            return jsonify({'erro': 'Canal não encontrado'}), 404
            
        segmento = request.args.get('segment', 'index.m3u8')
        token = request.args.get('token')
        stream_key = request.args.get('key')
        
        # Validação adicional de segurança
        if not stream_key or stream_key != request.stream_key:
            return jsonify({'mensagem': 'achou que era mais esperto kkkkk'}), 403
            
        # Validação do canal
        if channel_id != request.channel:
            return jsonify({'mensagem': 'achou que era mais esperto kkkkk'}), 403
        
        segmento = segmento.replace('..', '').strip('/')
        
        if segmento == 'index.m3u8':
            url = CHANNELS[channel_id]['url']
            base_url = url.rsplit('/', 1)[0]
        else:
            base_url = CHANNELS[channel_id]['url'].rsplit('/', 1)[0]
            url = urljoin(base_url + '/', segmento)
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': '*/*',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        }
        
        response = requests.get(url, headers=headers)
        
        if response.status_code != 200:
            return jsonify({'erro': 'Erro ao acessar o stream'}), response.status_code
        
        if segmento.endswith('.m3u8'):
            modified_content = modify_m3u8_content(response.text, token, stream_key, channel_id)
            return Response(
                modified_content,
                mimetype='application/vnd.apple.mpegurl',
                headers={
                    'Cache-Control': 'no-cache, no-store, must-revalidate',
                    'Pragma': 'no-cache',
                    'Expires': '0'
                }
            )
        
        return Response(
            response.content,
            mimetype='video/MP2T' if segmento.endswith('.ts') else 'application/octet-stream',
            headers={
                'Cache-Control': 'no-cache, no-store, must-revalidate',
                'Pragma': 'no-cache',
                'Expires': '0'
            }
        )
        
    except Exception as e:
        return jsonify({'erro': str(e)}), 500

@app.route('/<channel_id>')
def index(channel_id):
    if not check_referer():
        return jsonify({'mensagem': 'achou que era mais esperto kkkkk'}), 403
        
    if channel_id not in CHANNELS_PUBLIC:
        return jsonify({'erro': 'Canal não encontrado'}), 404
    return render_template('index.html', channel_id=channel_id, channel_name=CHANNELS_PUBLIC[channel_id]['name'])

if __name__ == '__main__':
    print("Domínios permitidos:", ALLOWED_DOMAINS)
    app.run(host='0.0.0.0', port=5001, debug=False) 
