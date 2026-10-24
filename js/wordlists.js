/*!
 * SworfishGuard — Word lists for passphrases (256 words each = exactly 8 bits per word).
 * Simple, common words without accents so they are easy to type on any keyboard.
 * Author: Asaf Rojas (Sworfish Tech) — MIT License
 */
(function (root) {
  'use strict';

  var es = [
    'abeja', 'agua', 'aire', 'amarillo', 'ancla', 'anillo', 'antena', 'arbol', 'ardilla', 'arena',
    'aro', 'avion', 'azul', 'banco', 'bandera', 'barco', 'barro', 'blanco', 'bolsa', 'bosque',
    'bota', 'botella', 'brazo', 'burro', 'caballo', 'cabra', 'cactus', 'caja', 'calle', 'cama',
    'camino', 'campana', 'campo', 'canal', 'canoa', 'carro', 'carta', 'casa', 'castillo', 'cebolla',
    'cesta', 'chispa', 'cielo', 'cine', 'cinta', 'circo', 'ciudad', 'clavo', 'cobre', 'cocina',
    'codo', 'cohete', 'collar', 'color', 'cometa', 'concha', 'conejo', 'copa', 'coral', 'corona',
    'cubo', 'cuchara', 'cuento', 'cuerda', 'cueva', 'dado', 'diente', 'disco', 'dorado', 'dulce',
    'duna', 'eco', 'elefante', 'escoba', 'espejo', 'estrella', 'estufa', 'faro', 'flecha', 'flor',
    'foco', 'fresa', 'fruta', 'fuego', 'fuente', 'galleta', 'gallo', 'ganso', 'garza', 'gato',
    'globo', 'gorra', 'gota', 'granja', 'grano', 'gris', 'guitarra', 'hacha', 'hada', 'hielo',
    'hierro', 'hilo', 'hoja', 'hormiga', 'horno', 'huevo', 'isla', 'jarra', 'jirafa', 'juego',
    'koala', 'lago', 'lana', 'lancha', 'leche', 'lente', 'libro', 'lima', 'lirio', 'llave',
    'lluvia', 'lobo', 'lodo', 'loro', 'luna', 'madera', 'maleta', 'mango', 'mano', 'manta',
    'manzana', 'mapa', 'mar', 'marco', 'mariposa', 'martillo', 'medalla', 'mesa', 'miel', 'mochila',
    'molino', 'moneda', 'mono', 'morado', 'mosca', 'motor', 'muro', 'naranja', 'negro', 'nido',
    'nieve', 'noche', 'nota', 'nube', 'nuez', 'ola', 'olla', 'oro', 'oso', 'oveja', 'pala', 'palma',
    'paloma', 'pan', 'panda', 'papel', 'parque', 'pasto', 'pato', 'pavo', 'pelota', 'pera', 'perla',
    'perro', 'pez', 'piano', 'piedra', 'pila', 'pino', 'pintura', 'pinza', 'pipa', 'planeta',
    'plata', 'plato', 'playa', 'pluma', 'pollo', 'polvo', 'pozo', 'prado', 'pueblo', 'puente',
    'puerta', 'pulpo', 'pulsera', 'queso', 'radio', 'rama', 'ramo', 'rana', 'red', 'regla', 'reloj',
    'remo', 'risa', 'roca', 'rojo', 'rosa', 'rosado', 'rueda', 'sal', 'salsa', 'sapo', 'selva',
    'semilla', 'sierra', 'silla', 'sirena', 'sobre', 'sol', 'sombra', 'sopa', 'tambor', 'tapa',
    'taza', 'techo', 'tela', 'tesoro', 'tierra', 'tigre', 'tijera', 'tinta', 'toalla', 'tomate',
    'toro', 'torre', 'tortuga', 'tren', 'trigo', 'trompeta', 'tubo', 'tuna', 'uva', 'vaca', 'valle',
    'vapor', 'vaso', 'vela', 'ventana', 'verde', 'viento', 'yogur', 'zanahoria', 'zapato', 'zorro'
  ];

  var en = [
    'apple', 'arrow', 'badge', 'bagel', 'baker', 'balloon', 'banana', 'basket', 'beach', 'bean',
    'bear', 'bell', 'berry', 'bike', 'bird', 'blanket', 'boat', 'bone', 'book', 'boot', 'bottle',
    'bread', 'brick', 'bridge', 'brush', 'bucket', 'butter', 'button', 'cabin', 'cactus', 'cake',
    'camel', 'camera', 'candle', 'candy', 'canoe', 'canyon', 'carpet', 'carrot', 'castle', 'cat',
    'cave', 'chair', 'chalk', 'cherry', 'chess', 'clock', 'cloud', 'coach', 'coconut', 'coffee',
    'comet', 'compass', 'cookie', 'coral', 'corn', 'cotton', 'cow', 'crab', 'crayon', 'crown',
    'cup', 'daisy', 'desert', 'diamond', 'dinner', 'dog', 'dolphin', 'donkey', 'door', 'dream',
    'drum', 'duck', 'eagle', 'earth', 'egg', 'engine', 'falcon', 'feather', 'fence', 'fern',
    'field', 'fig', 'finger', 'fire', 'fish', 'flag', 'flame', 'flower', 'flute', 'forest', 'fork',
    'fox', 'frog', 'fruit', 'garden', 'garlic', 'ghost', 'gift', 'giraffe', 'glass', 'globe',
    'glove', 'goat', 'gold', 'grape', 'grass', 'guitar', 'hammer', 'harbor', 'hat', 'hawk', 'heart',
    'hill', 'honey', 'horse', 'house', 'ice', 'island', 'jacket', 'jar', 'jelly', 'jungle', 'kayak',
    'kettle', 'key', 'kite', 'koala', 'ladder', 'lake', 'lamp', 'lemon', 'letter', 'lily', 'lion',
    'lizard', 'lobster', 'lock', 'magnet', 'mango', 'map', 'maple', 'marble', 'meadow', 'melon',
    'mirror', 'monkey', 'moon', 'moose', 'mountain', 'mouse', 'mug', 'mushroom', 'needle', 'nest',
    'ocean', 'olive', 'onion', 'orange', 'otter', 'owl', 'paddle', 'panda', 'paper', 'parrot',
    'peach', 'peanut', 'pear', 'pebble', 'pencil', 'pepper', 'piano', 'pickle', 'pigeon', 'pillow',
    'pine', 'pirate', 'pizza', 'planet', 'plum', 'pocket', 'pond', 'potato', 'pumpkin', 'puzzle',
    'rabbit', 'radio', 'rain', 'river', 'robot', 'rocket', 'rope', 'rose', 'ruby', 'saddle',
    'salad', 'salmon', 'sand', 'sandal', 'saturn', 'scarf', 'seal', 'seed', 'shark', 'sheep',
    'shell', 'ship', 'shoe', 'silver', 'skate', 'sky', 'snail', 'snake', 'snow', 'sock', 'sofa',
    'spider', 'spoon', 'squid', 'star', 'stone', 'storm', 'straw', 'stream', 'sugar', 'sun', 'swan',
    'sweater', 'table', 'taco', 'tea', 'tent', 'tiger', 'toast', 'tomato', 'tooth', 'torch',
    'tower', 'tractor', 'train', 'tree', 'truck', 'tulip', 'turtle', 'umbrella', 'valley', 'vase',
    'violin', 'volcano', 'wagon', 'walnut', 'water', 'whale', 'wheel', 'window', 'wolf'
  ];

  var lists = Object.freeze({ es: Object.freeze(es), en: Object.freeze(en) });
  root.SworfishGuard = root.SworfishGuard || {};
  root.SworfishGuard.words = lists;
  if (typeof module !== 'undefined' && module.exports) module.exports = lists;
})(typeof window !== 'undefined' ? window : globalThis);
