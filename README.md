# Sistema de Esteganografia LSB Avançada

Projeto de exame - Sistemas Multimédia

## Funcionalidades
- Backend Python puro (sem framework web)
- Autenticação JWT + registo/login/logout/eliminar conta
- Ocultação e extração de ficheiros em imagens PNG
- Histórico de operações e logs de atividades
- Inovação: compressão zlib antes da ocultação (aumenta capacidade)

## Como executar
1. Entre na pasta backend
2. Ative o venv: `source venv/bin/activate`
3. Instale dependências: `pip install -r requirements.txt`
4. Execute o servidor: `python3 app.py`
5. Abra `frontend/index.html` no navegador

Login padrão: admin / admin123