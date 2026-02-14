import base64
import random
from io import BytesIO
from PIL import Image
import hashlib
from typing import Tuple
import zlib

class AdvancedLSBSteganography:
    
    @staticmethod
    def seeded_random(seed):
        rng = random.Random()
        rng.seed(seed)
        return rng
    
    @staticmethod
    def get_deterministic_seed(key: str) -> int:

        key_bytes = key.encode('utf-8')
        hash_bytes = hashlib.sha256(key_bytes).digest()
        return int.from_bytes(hash_bytes[:4], 'big') % (2**32)
    
    @staticmethod
    def simple_hash(data):

        if isinstance(data, str):
            data = data.encode()
        return int(hashlib.md5(data).hexdigest()[:8], 16)
    
    @staticmethod
    def xor_crypt(data, key):
        
        if isinstance(data, str):
            data = data.encode()
        if isinstance(key, str):
            key = key.encode()
        
        key_bytes = key
        result = bytearray(data)
        for i in range(len(result)):
            result[i] ^= key_bytes[i % len(key_bytes)]
        return bytes(result)
    
    @staticmethod
    def compress_data(data):
       
        return zlib.compress(data)
    
    @staticmethod
    def decompress_data(data):
        
        return zlib.decompress(data)
    
    @staticmethod
    def encode_image(cover_image_b64: str, secret_data_b64: str, 
                     secret_filename: str, key: str, compress: bool = True) -> str:
        try:
            cover_data = base64.b64decode(cover_image_b64)
            img = Image.open(BytesIO(cover_data))
            
            if img.mode != 'RGB':
                img = img.convert('RGB')
            
            width, height = img.size
            pixels = list(img.getdata())
            
            secret_data = base64.b64decode(secret_data_b64)
            
            if compress:
                secret_data = AdvancedLSBSteganography.compress_data(secret_data)
            
            encrypted = AdvancedLSBSteganography.xor_crypt(secret_data, key)
            hash_value = AdvancedLSBSteganography.simple_hash(secret_data)
            
            name_bytes = secret_filename.encode('utf-8')
            header = bytearray()
            header.append(1)  
            header.append(0x01 if compress else 0x00)  
            header.extend(len(name_bytes).to_bytes(2, 'big'))
            header.extend(len(encrypted).to_bytes(4, 'big'))
            header.extend(hash_value.to_bytes(8, 'big'))
            header.extend(name_bytes)
            
            payload = bytes(header) + encrypted
            
            capacity = width * height * 3
            if len(payload) * 8 > capacity:
                raise ValueError(f"Imagem insuficiente: precisa de {len(payload)*8} bits, tem {capacity}")
            
            
            seed = AdvancedLSBSteganography.get_deterministic_seed(key)
            rand = AdvancedLSBSteganography.seeded_random(seed)
            positions = list(range(capacity))
            rand.shuffle(positions)
            
            pixel_list = [ch for pixel in pixels for ch in pixel]
            
            bit_index = 0
            for pos in positions:
                if bit_index >= len(payload) * 8:
                    break
                byte_idx = bit_index // 8
                bit_pos = 7 - (bit_index % 8)
                bit = (payload[byte_idx] >> bit_pos) & 1
                pixel_list[pos] = (pixel_list[pos] & 0xFE) | bit
                bit_index += 1
            
            new_pixels = [tuple(pixel_list[i:i+3]) for i in range(0, len(pixel_list), 3)]
            
            encoded_img = Image.new('RGB', (width, height))
            encoded_img.putdata(new_pixels)
            
            buffer = BytesIO()
            encoded_img.save(buffer, format='PNG')
            buffer.seek(0)
            
            return base64.b64encode(buffer.getvalue()).decode('utf-8')
            
        except Exception as e:
            raise Exception(f"Erro na codificação: {str(e)}")
    
    @staticmethod
    def decode_image(stego_image_b64: str, key: str) -> Tuple[str, str, bool]:
        try:
            stego_data = base64.b64decode(stego_image_b64)
            img = Image.open(BytesIO(stego_data))
            
            if img.mode != 'RGB':
                img = img.convert('RGB')
            
            width, height = img.size
            pixels = list(img.getdata())
            
            pixel_list = []
            for pixel in pixels:
                pixel_list.extend(pixel)
            
            capacity = len(pixel_list)
            
            
            seed = AdvancedLSBSteganography.get_deterministic_seed(key)
            rand = AdvancedLSBSteganography.seeded_random(seed)
            positions = list(range(capacity))
            rand.shuffle(positions)
            
            bytes_data = bytearray()
            byte_value = 0
            bit_count = 0
            total_needed = None
            
            for pos in positions:
                bit = pixel_list[pos] & 1
                byte_value = (byte_value << 1) | bit
                bit_count += 1
                
                if bit_count == 8:
                    bytes_data.append(byte_value)
                    byte_value = 0
                    bit_count = 0
                    
                    if len(bytes_data) >= 16 and total_needed is None:
                        view = bytes(bytes_data)
                        name_len = int.from_bytes(view[2:4], 'big')
                        data_len = int.from_bytes(view[4:8], 'big')
                        total_needed = 16 + name_len + data_len
                        
                        if total_needed > len(pixel_list) // 8:
                            raise ValueError(f"Tamanho declarado irrealista: {total_needed} bytes")
                    
                    if total_needed is not None and len(bytes_data) >= total_needed:
                        break
            
            if total_needed is None or len(bytes_data) < total_needed:
                raise ValueError(f"Dados insuficientes para payload. Header indica {total_needed or 'desconhecido'} bytes, mas só temos {len(bytes_data)} bytes.")
            
            view = bytes(bytes_data)
            
            version = view[0]
            flags = view[1]
            name_len = int.from_bytes(view[2:4], 'big')
            data_len = int.from_bytes(view[4:8], 'big')
            stored_hash = int.from_bytes(view[8:16], 'big')
            
            header_size = 16 + name_len
            name_bytes = view[16:header_size]
            encrypted = view[header_size:header_size + data_len]
            
            decrypted = AdvancedLSBSteganography.xor_crypt(encrypted, key)
            
            if AdvancedLSBSteganography.simple_hash(decrypted) != stored_hash:
                raise ValueError("Hash inválido - chave incorreta ou corrupção")
            
            compression_used = (flags & 0x01) != 0
            if compression_used:
                decrypted = AdvancedLSBSteganography.decompress_data(decrypted)
            
            filename = name_bytes.decode('utf-8', errors='replace')
            data_b64 = base64.b64encode(decrypted).decode('utf-8')
            
            return filename, data_b64, compression_used
        
        except Exception as e:
            import traceback
            traceback.print_exc()
            raise Exception(f"Erro na decodificação: {str(e)}")


if __name__ == "__main__":
    print("Teste local de encode + decode...")
    test_img = Image.new('RGB', (1000, 1000), color=(73, 109, 137))
    buffer = BytesIO()
    test_img.save(buffer, format='PNG')
    cover_b64 = base64.b64encode(buffer.getvalue()).decode('utf-8')

    secret = "Teste secreto para validar decode".encode('utf-8')
    secret_b64 = base64.b64encode(secret).decode('utf-8')
    key = "chave_teste123"
    filename = "teste_secreto.txt"

    encoded_b64 = AdvancedLSBSteganography.encode_image(cover_b64, secret_b64, filename, key, compress=True)
    print("✅ Encode concluído")

    try:
        dec_filename, dec_data_b64, compressed = AdvancedLSBSteganography.decode_image(encoded_b64, key)
        decrypted = base64.b64decode(dec_data_b64)
        print("✅ Decode concluído!")
        print(f"Nome: {dec_filename}")
        print(f"Compressão: {compressed}")
        print(f"Dados: {decrypted.decode('utf-8', errors='ignore')}")
    except Exception as e:
        print(f"❌ Erro no decode: {e}")