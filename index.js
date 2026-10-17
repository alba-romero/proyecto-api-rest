import { MongoClient, ObjectId } from 'mongodb'
import express from 'express'
import cors from 'cors'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import swaggerJsdoc from 'swagger-jsdoc'
import { rateLimit } from 'express-rate-limit'
import path from 'path'

// ---------------------------------------------------
// CONFIGURACIÓN
// ---------------------------------------------------

const PORT = process.env.PORT ?? 3002
const DB_URL = process.env.MONGODB_URI ?? 'mongodb://localhost:27017'
const DB_NAME = process.env.DB_NAME ?? 'api'
const ACCESS_SECRET = process.env.JWT_ACCESS_SECRET
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET

// Conexión a MongoDB y las dos colecciones que usamos
const client = new MongoClient(DB_URL)
const usuarios = client.db(DB_NAME).collection('usuarios')
const tareas = client.db(DB_NAME).collection('tareas')

const app = express()

// Vercel está detrás de un proxy: así el rate limit ve la IP real del cliente
app.set('trust proxy', 1)

app.use(express.json())
app.use(cors())

// ---------------------------------------------------
// RATE LIMIT (limitar peticiones)
// ---------------------------------------------------

// Límite general: 100 peticiones cada 15 minutos por IP en toda la API
const limiteApi = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 100,
    message: { message: 'Demasiadas peticiones. Inténtalo más tarde.' }
})

// Límite más estricto para el login: 5 intentos cada 15 minutos (evita ataques de fuerza bruta)
const limiteLogin = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 5,
    message: { message: 'Demasiados intentos de login. Inténtalo en 15 minutos.' }
})

app.use('/api', limiteApi)

// ---------------------------------------------------
// FUNCIONES AUXILIARES
// ---------------------------------------------------

// Respuesta común cuando falla algo inesperado (por ejemplo, la base de datos)
function errorServidor(response, error) {
    console.error(error)
    response.status(500).json({ message: 'Error del servidor' })
}

// Middleware: comprueba que la petición trae un access token válido
function verifyToken(request, response, next) {
    const token = request.headers.authorization?.split(' ')[1]

    if (!token) {
        return response.status(401).json({ message: 'Token requerido' })
    }

    try {
        request.user = jwt.verify(token, ACCESS_SECRET)
        next()
    } catch (error) {
        response.status(403).json({ message: 'Token inválido o caducado' })
    }
}

// ---------------------------------------------------
// SWAGGER (documentación)
// ---------------------------------------------------

const swaggerSpec = swaggerJsdoc({
    definition: {
        openapi: '3.0.0',
        info: {
            title: 'API de gestión de tareas',
            version: '1.0.0',
            description: 'API REST para gestionar tareas con autenticación JWT'
        },
        servers: [{ url: '/' }],
        components: {
            securitySchemes: {
                bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' }
            },
            schemas: {
                Tarea: {
                    type: 'object',
                    properties: {
                        _id: { type: 'string' },
                        titulo: { type: 'string' },
                        descripcion: { type: 'string' },
                        completada: { type: 'boolean' },
                        fechaLimite: { type: 'string', nullable: true },
                        usuarioId: { type: 'string' }
                    }
                },
                TareaInput: {
                    type: 'object',
                    required: ['titulo'],
                    properties: {
                        titulo: { type: 'string', example: 'Estudiar para el examen' },
                        descripcion: { type: 'string', example: 'Repasar REST y JWT' },
                        completada: { type: 'boolean', example: false },
                        fechaLimite: { type: 'string', example: '2026-10-20' }
                    }
                },
                LoginRequest: {
                    type: 'object',
                    required: ['email', 'password'],
                    properties: {
                        email: { type: 'string', example: 'alumno1@example.com' },
                        password: { type: 'string', example: 'ClavePrueba123' }
                    }
                },
                LoginResponse: {
                    type: 'object',
                    properties: {
                        message: { type: 'string' },
                        accessToken: { type: 'string' },
                        refreshToken: { type: 'string' }
                    }
                },
                MessageResponse: {
                    type: 'object',
                    properties: {
                        message: { type: 'string' }
                    }
                }
            }
        }
    },
    // Fichero donde swagger-jsdoc busca los comentarios @swagger (este mismo)
    apis: [path.join(process.cwd(), 'index.js')]
})

// Página HTML de Swagger. Carga los ficheros desde un CDN porque en Vercel
// no están disponibles los de swagger-ui-express (por eso daba pantalla en blanco)
const swaggerHtml = `<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8" />
  <title>API de gestión de tareas</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.17.14/swagger-ui.css" />
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.17.14/swagger-ui-bundle.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.17.14/swagger-ui-standalone-preset.js"></script>
  <script>
    window.onload = () => {
      SwaggerUIBundle({
        url: '/api-docs.json',
        dom_id: '#swagger-ui',
        validatorUrl: null,
        presets: [SwaggerUIBundle.presets.apis, SwaggerUIStandalonePreset],
        layout: 'StandaloneLayout'
      })
    }
  </script>
</body>
</html>`

app.get('/api-docs.json', (request, response) => response.json(swaggerSpec))
app.get('/api-docs', (request, response) => response.type('html').send(swaggerHtml))

// La página principal lleva a la documentación
app.get('/', (request, response) => {
    response.redirect('/api-docs')
})

// ---------------------------------------------------
// AUTENTICACIÓN (login y refresh)
// ---------------------------------------------------

/**
 * @swagger
 * /api/login:
 *   post:
 *     summary: Iniciar sesión
 *     description: Comprueba las credenciales y devuelve un access token (15 min) y un refresh token (7 días).
 *     tags: [Autenticación]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/LoginRequest'
 *     responses:
 *       200:
 *         description: Inicio de sesión correcto
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/LoginResponse'
 *       400:
 *         description: Faltan datos
 *       401:
 *         description: Credenciales incorrectas
 *       429:
 *         description: Demasiados intentos de login
 */
app.post('/api/login', limiteLogin, async (request, response) => {
    try {
        const { email, password } = request.body

        if (!email || !password) {
            return response.status(400).json({ message: 'Email y contraseña son obligatorios' })
        }

        const usuario = await usuarios.findOne({ email })

        if (!usuario) {
            return response.status(401).json({ message: 'Credenciales incorrectas' })
        }

        // Compara la contraseña escrita con la cifrada que hay guardada
        const passwordCorrecta = await bcrypt.compare(password, usuario.password)

        if (!passwordCorrecta) {
            return response.status(401).json({ message: 'Credenciales incorrectas' })
        }

        // Datos que van dentro de los tokens (nunca la contraseña)
        const datosUsuario = {
            id: usuario._id.toString(),
            nombre: usuario.nombre,
            email: usuario.email
        }

        const accessToken = jwt.sign(datosUsuario, ACCESS_SECRET, { expiresIn: '15m' })
        const refreshToken = jwt.sign(datosUsuario, REFRESH_SECRET, { expiresIn: '7d' })

        response.status(200).json({
            message: 'Inicio de sesión correcto',
            accessToken,
            refreshToken
        })
    } catch (error) {
        errorServidor(response, error)
    }
})

/**
 * @swagger
 * /api/refresh:
 *   post:
 *     summary: Renovar el access token
 *     description: Genera un nuevo access token usando un refresh token válido.
 *     tags: [Autenticación]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [refreshToken]
 *             properties:
 *               refreshToken:
 *                 type: string
 *     responses:
 *       200:
 *         description: Access token renovado
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 accessToken:
 *                   type: string
 *       401:
 *         description: Refresh token requerido
 *       403:
 *         description: Refresh token inválido o caducado
 */
app.post('/api/refresh', (request, response) => {
    const { refreshToken } = request.body

    if (!refreshToken) {
        return response.status(401).json({ message: 'Refresh token requerido' })
    }

    try {
        const datos = jwt.verify(refreshToken, REFRESH_SECRET)

        // Creamos el nuevo token solo con id, nombre y email
        const accessToken = jwt.sign(
            { id: datos.id, nombre: datos.nombre, email: datos.email },
            ACCESS_SECRET,
            { expiresIn: '15m' }
        )

        response.status(200).json({ accessToken })
    } catch (error) {
        response.status(403).json({ message: 'Refresh token inválido o caducado' })
    }
})

// ---------------------------------------------------
// TAREAS (crear, modificar y borrar necesitan access token)
// ---------------------------------------------------

/**
 * @swagger
 * /api/tareas:
 *   get:
 *     summary: Obtener todas las tareas
 *     tags: [Tareas]
 *     responses:
 *       200:
 *         description: Lista de tareas
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 $ref: '#/components/schemas/Tarea'
 */
app.get('/api/tareas', async (request, response) => {
    try {
        const resultado = await tareas.find({}).toArray()
        response.status(200).json(resultado)
    } catch (error) {
        errorServidor(response, error)
    }
})

/**
 * @swagger
 * /api/tareas:
 *   post:
 *     summary: Crear una tarea
 *     tags: [Tareas]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/TareaInput'
 *     responses:
 *       201:
 *         description: Tarea creada
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Tarea'
 *       400:
 *         description: El título es obligatorio
 *       401:
 *         description: Token requerido
 *       403:
 *         description: Token inválido o caducado
 */
app.post('/api/tareas', verifyToken, async (request, response) => {
    try {
        const { titulo, descripcion, completada, fechaLimite } = request.body

        if (!titulo) {
            return response.status(400).json({ message: 'El título es obligatorio' })
        }

        const nuevaTarea = {
            titulo,
            descripcion: descripcion ?? '',
            completada: completada ?? false,
            fechaLimite: fechaLimite ?? null,
            usuarioId: request.user.id // viene del token
        }

        const resultado = await tareas.insertOne(nuevaTarea)

        response.status(201).json({ _id: resultado.insertedId, ...nuevaTarea })
    } catch (error) {
        errorServidor(response, error)
    }
})

/**
 * @swagger
 * /api/tareas/{id}:
 *   get:
 *     summary: Obtener una tarea por su ID
 *     tags: [Tareas]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Tarea encontrada
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Tarea'
 *       400:
 *         description: ID no válido
 *       404:
 *         description: Tarea no encontrada
 */
app.get('/api/tareas/:id', async (request, response) => {
    try {
        const { id } = request.params

        if (!ObjectId.isValid(id)) {
            return response.status(400).json({ message: 'ID no válido' })
        }

        const tarea = await tareas.findOne({ _id: new ObjectId(id) })

        if (!tarea) {
            return response.status(404).json({ message: 'Tarea no encontrada' })
        }

        response.status(200).json(tarea)
    } catch (error) {
        errorServidor(response, error)
    }
})

/**
 * @swagger
 * /api/tareas/{id}:
 *   put:
 *     summary: Modificar una tarea
 *     description: Reemplaza los datos de la tarea, así que hay que enviar todos los campos.
 *     tags: [Tareas]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/TareaInput'
 *     responses:
 *       200:
 *         description: Tarea modificada
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/MessageResponse'
 *       400:
 *         description: ID o datos no válidos
 *       401:
 *         description: Token requerido
 *       403:
 *         description: Token inválido o caducado
 *       404:
 *         description: Tarea no encontrada
 */
app.put('/api/tareas/:id', verifyToken, async (request, response) => {
    try {
        const { id } = request.params
        const { titulo, descripcion, completada, fechaLimite } = request.body

        if (!ObjectId.isValid(id)) {
            return response.status(400).json({ message: 'ID no válido' })
        }

        if (!titulo) {
            return response.status(400).json({ message: 'El título es obligatorio' })
        }

        const resultado = await tareas.updateOne(
            { _id: new ObjectId(id) },
            {
                $set: {
                    titulo,
                    descripcion: descripcion ?? '',
                    completada: completada ?? false,
                    fechaLimite: fechaLimite ?? null
                }
            }
        )

        if (resultado.matchedCount === 0) {
            return response.status(404).json({ message: 'Tarea no encontrada' })
        }

        response.status(200).json({ message: 'Tarea modificada correctamente' })
    } catch (error) {
        errorServidor(response, error)
    }
})

/**
 * @swagger
 * /api/tareas/{id}:
 *   delete:
 *     summary: Eliminar una tarea
 *     tags: [Tareas]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Tarea eliminada
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/MessageResponse'
 *       400:
 *         description: ID no válido
 *       401:
 *         description: Token requerido
 *       403:
 *         description: Token inválido o caducado
 *       404:
 *         description: Tarea no encontrada
 */
app.delete('/api/tareas/:id', verifyToken, async (request, response) => {
    try {
        const { id } = request.params

        if (!ObjectId.isValid(id)) {
            return response.status(400).json({ message: 'ID no válido' })
        }

        const resultado = await tareas.deleteOne({ _id: new ObjectId(id) })

        if (resultado.deletedCount === 0) {
            return response.status(404).json({ message: 'Tarea no encontrada' })
        }

        response.status(200).json({ message: 'Tarea eliminada correctamente' })
    } catch (error) {
        errorServidor(response, error)
    }
})

// ---------------------------------------------------
// ARRANQUE
// ---------------------------------------------------

// En local arrancamos el servidor; en Vercel no hace falta (usa la app exportada)
if (!process.env.VERCEL) {
    app.listen(PORT, () => {
        console.log(`Servidor web iniciado en puerto: ${PORT}`)
    })
}

export default app

