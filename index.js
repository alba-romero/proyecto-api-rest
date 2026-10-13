import { MongoClient, ObjectId } from 'mongodb'
import express from "express"
import cors from "cors"
import bcrypt from "bcryptjs"
import jwt from "jsonwebtoken"
import swaggerJsdoc from 'swagger-jsdoc'
import path from 'path'
import { rateLimit } from 'express-rate-limit'
const ACCESS_SECRET = process.env.JWT_ACCESS_SECRET
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET


function verifyToken(request, response, next) {
    const authHeader = request.headers.authorization
    const token = authHeader?.split(' ')[1]

    if (!token) {
        return response.status(401).json({
            message: 'Token requerido'
        })
    }

    try {
        request.user = jwt.verify(token, ACCESS_SECRET)
        next()
    } catch (error) {
        return response.status(403).json({
            message: 'Token inválido o caducado'
        })
    }
}


const app = express()

// Necesario en Vercel (proxy) para que el rate limit vea la IP real del cliente
app.set('trust proxy', 1)

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 5,
    message: {
        error: 'Demasiados intentos de inicio de sesión. Inténtalo de nuevo dentro de 15 minutos.'
    },
    standardHeaders: true,
    legacyHeaders: false
})

// Límite general para toda la API: 100 peticiones cada 15 minutos por IP
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 100,
    message: {
        message: 'Demasiadas peticiones. Inténtalo de nuevo más tarde.'
    },
    standardHeaders: true,
    legacyHeaders: false
})




const swaggerOptions = {
    definition: {
        openapi: '3.0.0',
        info: { title: 'API de gestión de tareas',
            version: '1.0.0',
            description: 'API REST para gestionar usuarios y tareas'},
        servers: [
            { url: '/' }],
        components: {
    securitySchemes: {
        bearerAuth: {
            type: 'http',
            scheme: 'bearer',
            bearerFormat: 'JWT'
        }
    },
    schemas: {
        Tarea: {
            type: 'object',
            properties: {
                _id: { type: 'string', example: '6acb65b02f4f78b1aacc31f2' },
                titulo: { type: 'string', example: 'Estudiar para el examen' },
                descripcion: { type: 'string', example: 'Repasar REST y JWT' },
                completada: { type: 'boolean', example: false },
                fechaLimite: { type: 'string', nullable: true, example: '2026-10-20' },
                usuarioId: { type: 'string', example: '6acb5da72812188c162529bc' }
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
        Usuario: {
            type: 'object',
            properties: {
                _id: { type: 'string', example: '6acb5da72812188c162529bc' },
                nombre: { type: 'string', example: 'alumno1' },
                email: { type: 'string', example: 'alumno1@example.com' }
            }
        },
        LoginRequest: {
            type: 'object',
            required: ['email', 'password'],
            properties: {
                email: { type: 'string', example: 'prueba@gmail.com' },
                password: { type: 'string', example: 'Prueba123' }
            }
        },
        LoginResponse: {
            type: 'object',
            properties: {
                message: { type: 'string', example: 'Inicio de sesión correcto' },
                accessToken: { type: 'string' },
                refreshToken: { type: 'string' }
            }
        },
        MessageResponse: {
            type: 'object',
            properties: {
                message: { type: 'string', example: 'Credenciales incorrectas' }
            }
        }
    }
}
    },
    apis: [path.join(process.cwd(), 'index.js')]
}

const swaggerSpec = swaggerJsdoc(swaggerOptions)


app.use(express.json())
app.use(cors())
app.use('/api', apiLimiter)

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
      window.ui = SwaggerUIBundle({
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
const PORT = process.env.PORT ?? 3002
const DB_URL = process.env.MONGODB_URI ?? 'mongodb://localhost:27017'
const DB_NAME = process.env.DB_NAME ?? 'api'

const USERS = 'usuarios'
const TASKS = 'tareas'

const client = new MongoClient(DB_URL)

// Envuelve las rutas async para que cualquier error llegue al manejador de errores
const asyncHandler = (fn) => (request, response, next) =>
    Promise.resolve(fn(request, response, next)).catch(next)


// Página inicial
app.get("/", (request, response) => {
    response.redirect("/api-docs")
})

// -------------- USUARIOS ------------------

// GET: obtener todos los usuarios

/**
 * @swagger
 * /api/usuarios:
 *   get:
 *     summary: Obtener todos los usuarios
 *     tags: [Usuarios]
 *     responses:
 *       200:
 *         description: Lista de usuarios
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 $ref: '#/components/schemas/Usuario'
 */

app.get('/api/usuarios', asyncHandler(async (request, response) => {
    const database = client.db(DB_NAME)
    const collection = database.collection(USERS)

    const results = await collection.find({}, { projection: { password: 0 } }).toArray()

    response.status(200).json(results)
}))

// POST: crear un usuario


/**
 * @swagger
 * /api/usuarios:
 *   post:
 *     summary: Registrar un usuario
 *     tags: [Usuarios]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - nombre
 *               - email
 *               - password
 *             properties:
 *               nombre:
 *                 type: string
 *                 example: alumno1
 *               email:
 *                 type: string
 *                 example: alumno1@example.com
 *               password:
 *                 type: string
 *                 format: password
 *                 example: ClavePrueba123!
 *     responses:
 *       201:
 *         description: Usuario registrado
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Usuario'
 *       400:
 *         description: Datos obligatorios no proporcionados
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/MessageResponse'
 *       409:
 *         description: El usuario o email ya existe
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/MessageResponse'
 */

  
app.post('/api/usuarios', asyncHandler(async (request, response) => {
    if (!request.is('json')) {
        return response.status(400).json({
            message: 'Debes proporcionar datos JSON'
        })
    }

    const { nombre, email, password } = request.body

    if (!nombre || !email || !password) {
        return response.status(400).json({
            message: 'Nombre, email y contraseña son obligatorios'
        })
    }

    const database = client.db(DB_NAME)
    const collection = database.collection(USERS)

    const usuarioExistente = await collection.findOne({
        $or: [
            { nombre },
            { email }
        ]
    })

    if (usuarioExistente) {
        return response.status(409).json({
            message: 'El nombre o el email ya están registrados'
        })
    }

    const passwordCifrada = await bcrypt.hash(password, 10)

    const nuevoUsuario = {
        nombre,
        email,
        password: passwordCifrada
    }

    const resultado = await collection.insertOne(nuevoUsuario)

    response.status(201).json({
        _id: resultado.insertedId,
        nombre,
        email
    })
}))


// GET: obtener un usuario por ID



/**
 * @swagger
 * /api/usuarios/{id}:
 *   get:
 *     summary: Obtener un usuario por su ID
 *     tags: [Usuarios]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Identificador del usuario
 *     responses:
 *       200:
 *         description: Usuario encontrado
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Usuario'
 *       400:
 *         description: ID no válido
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/MessageResponse'
 *       404:
 *         description: Usuario no encontrado
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/MessageResponse'
 */

app.get('/api/usuarios/:id', asyncHandler(async (request, response) => {
    const database = client.db(DB_NAME)
    const collection = database.collection(USERS)

    const { id } = request.params

    if (!ObjectId.isValid(id)) {
        return response.status(400).json({
            message: 'ID no válido'
        })
    }

    const result = await collection.findOne(
        { _id: new ObjectId(id) },
        { projection: { password: 0 } }
    )

    if (!result) {
        return response.status(404).json({
            message: 'Usuario no encontrado'
        })
    }

    response.status(200).json(result)
}))

// PUT: actualizar un usuario

/**
 * @swagger
 * /api/usuarios/{id}:
 *   put:
 *     summary: Modificar un usuario
 *     tags: [Usuarios]
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
 *             type: object
 *             properties:
 *               nombre:
 *                 type: string
 *               email:
 *                 type: string
 *     responses:
 *       200:
 *         description: Usuario modificado
 *       400:
 *         description: ID o datos no válidos
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/MessageResponse'
 *       404:
 *         description: Usuario no encontrado
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/MessageResponse'
 */

app.put('/api/usuarios/:id', asyncHandler(async (request, response) => {
    if (!request.is('json')) {
        return response.status(400).json({
            message: 'Debes proporcionar datos JSON'
        })
    }

    const { id } = request.params

    if (!ObjectId.isValid(id)) {
        return response.status(400).json({
            message: 'ID no válido'
        })
    }

    const database = client.db(DB_NAME)
    const collection = database.collection(USERS)
    const { nombre, email } = request.body

    const results = await collection.updateOne(
        { _id: new ObjectId(id) },
        { $set: { nombre, email } }
    )

    if (results.matchedCount === 0) {
        return response.status(404).json({
            message: 'Usuario no encontrado'
        })
    }

    response.status(200).json(results)
}))

// DELETE: eliminar un usuario

/**
 * @swagger
 * /api/usuarios/{id}:
 *   delete:
 *     summary: Eliminar un usuario
 *     tags: [Usuarios]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Usuario eliminado
 *       400:
 *         description: ID no válido
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/MessageResponse'
 *       404:
 *         description: Usuario no encontrado
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/MessageResponse'
 */

app.delete('/api/usuarios/:id', asyncHandler(async (request, response) => {
    const { id } = request.params

    if (!ObjectId.isValid(id)) {
        return response.status(400).json({
            message: 'ID no válido'
        })
    }

    const database = client.db(DB_NAME)
    const collection = database.collection(USERS)

    const results = await collection.deleteOne({
        _id: new ObjectId(id)
    })

    if (results.deletedCount === 0) {
        return response.status(404).json({
            message: 'Usuario no encontrado'
        })
    }

    response.status(200).json(results)
}))

// -------------- TAREAS ------------------

// GET: obtener todas las tareas

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

app.get('/api/tareas', asyncHandler(async (request, response) => {
    const database = client.db(DB_NAME)
    const collection = database.collection(TASKS)

    const results = await collection.find({}).toArray()

    response.status(200).json(results)
}))

// POST: crear una tarea

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
 *         description: Datos no válidos o título no proporcionado
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/MessageResponse'
 *       401:
 *         description: Token requerido
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/MessageResponse'
 *       403:
 *         description: Token inválido o caducado
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/MessageResponse'
 */

app.post('/api/tareas', verifyToken, asyncHandler(async (request, response) => {
    if (!request.is('json')) {
        return response.status(400).json({
            message: 'Debes proporcionar datos JSON'
        })
    }

    const database = client.db(DB_NAME)
    const collection = database.collection(TASKS)

    const { titulo, descripcion, completada, fechaLimite } = request.body

    if (!titulo) {
        return response.status(400).json({
            message: 'El título es obligatorio'
        })
    }

    const nuevaTarea = {
    titulo,
    descripcion: descripcion ?? '',
    completada: completada ?? false,
    fechaLimite: fechaLimite ?? null,
    usuarioId: request.user.id
}

    const results = await collection.insertOne(nuevaTarea)

    response.status(201).json({
        _id: results.insertedId,
        ...nuevaTarea
    })
}))

/**
 * @swagger
 * /api/login:
 *   post:
 *     summary: Iniciar sesión
 *     description: Comprueba las credenciales y devuelve un access token y un refresh token.
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
 *         description: Faltan datos o el JSON no es válido
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/MessageResponse'
 *       401:
 *         description: Credenciales incorrectas
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/MessageResponse'
 *       429:
 *         description: Demasiados intentos de inicio de sesión
 */


app.post('/api/login', loginLimiter, asyncHandler(async (request, response) => {
    if (!request.is('json')) {
        return response.status(400).json({
            message: 'Debes proporcionar datos JSON'
        })
    }

    const { email, password } = request.body

    if (!email || !password) {
        return response.status(400).json({
            message: 'Email y contraseña son obligatorios'
        })
    }

    const database = client.db(DB_NAME)
    const collection = database.collection(USERS)

    const usuario = await collection.findOne({ email })

    if (!usuario) {
        return response.status(401).json({
            message: 'Credenciales incorrectas'
        })
    }

    const passwordCorrecta = await bcrypt.compare(
        password,
        usuario.password
    )

    if (!passwordCorrecta) {
        return response.status(401).json({
            message: 'Credenciales incorrectas'
        })
    }

    const datosUsuario = {
        id: usuario._id.toString(),
        nombre: usuario.nombre,
        email: usuario.email
    }

    const accessToken = jwt.sign(
        datosUsuario,
        ACCESS_SECRET,
        { expiresIn: '15m' }
    )

    const refreshToken = jwt.sign(
        datosUsuario,
        REFRESH_SECRET,
        { expiresIn: '7d' }
    )

    response.status(200).json({
        message: 'Inicio de sesión correcto',
        accessToken,
        refreshToken
    })
}))


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
 *             required:
 *               - refreshToken
 *             properties:
 *               refreshToken:
 *                 type: string
 *                 description: Refresh token obtenido al iniciar sesión.
 *     responses:
 *       200:
 *         description: Access token renovado correctamente
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 accessToken:
 *                   type: string
 *       401:
 *         description: Refresh token requerido
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/MessageResponse'
 *       403:
 *         description: Refresh token inválido o caducado
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/MessageResponse'
 */


app.post('/api/refresh', (request, response) => {
    const { refreshToken } = request.body

    if (!refreshToken) {
        return response.status(401).json({
            message: 'Refresh token requerido'
        })
    }

    try {
        const datosUsuario = jwt.verify(
            refreshToken,
            REFRESH_SECRET
        )

        const datosNuevos = {
            id: datosUsuario.id,
            nombre: datosUsuario.nombre,
            email: datosUsuario.email
        }

        const nuevoAccessToken = jwt.sign(
            datosNuevos,
            ACCESS_SECRET,
            { expiresIn: '15m' }
        )

        response.status(200).json({
            accessToken: nuevoAccessToken
        })
    } catch (error) {
        return response.status(403).json({
            message: 'Refresh token inválido o caducado'
        })
    }
})



// GET: obtener una tarea por ID

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
 *         description: Identificador de la tarea
 *     responses:
 *       200:
 *         description: Tarea encontrada
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Tarea'
 *       400:
 *         description: ID no válido
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/MessageResponse'
 *       404:
 *         description: Tarea no encontrada
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/MessageResponse'
 */

app.get('/api/tareas/:id', asyncHandler(async (request, response) => {
    const { id } = request.params

    if (!ObjectId.isValid(id)) {
        return response.status(400).json({
            message: 'ID no válido'
        })
    }

    const database = client.db(DB_NAME)
    const collection = database.collection(TASKS)

    const result = await collection.findOne({
        _id: new ObjectId(id)
    })

    if (!result) {
        return response.status(404).json({
            message: 'Tarea no encontrada'
        })
    }

    response.status(200).json(result)
}))

// PUT: actualizar una tarea por ID

/**
 * @swagger
 * /api/tareas/{id}:
 *   put:
 *     summary: Modificar una tarea
 *     tags: [Tareas]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Identificador de la tarea
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               titulo:
 *                 type: string
 *               descripcion:
 *                 type: string
 *               completada:
 *                 type: boolean
 *               fechaLimite:
 *                 type: string
 *                 nullable: true
 *     responses:
 *       200:
 *         description: Tarea modificada
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Tarea'
 *       400:
 *         description: Datos o ID no válidos
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/MessageResponse'
 *       401:
 *         description: Token requerido
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/MessageResponse'
 *       403:
 *         description: Token inválido o caducado
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/MessageResponse'
 *       404:
 *         description: Tarea no encontrada
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/MessageResponse'
 */

app.put('/api/tareas/:id', verifyToken, asyncHandler(async (request, response) => {
    if (!request.is('json')) {
        return response.status(400).json({
            message: 'Debes proporcionar datos JSON'
        })
    }

    const { id } = request.params

    if (!ObjectId.isValid(id)) {
        return response.status(400).json({
            message: 'ID no válido'
        })
    }

    const { titulo, descripcion, completada, fechaLimite } = request.body
    const cambios = {}

    if (titulo !== undefined) cambios.titulo = titulo
    if (descripcion !== undefined) cambios.descripcion = descripcion
    if (completada !== undefined) cambios.completada = completada
    if (fechaLimite !== undefined) cambios.fechaLimite = fechaLimite

    if (Object.keys(cambios).length === 0) {
        return response.status(400).json({
            message: 'Debes proporcionar algún campo para actualizar'
        })
    }

    const database = client.db(DB_NAME)
    const collection = database.collection(TASKS)

    const results = await collection.updateOne(
        { _id: new ObjectId(id) },
        { $set: cambios }
    )

    if (results.matchedCount === 0) {
        return response.status(404).json({
            message: 'Tarea no encontrada'
        })
    }

    const tareaActualizada = await collection.findOne({
        _id: new ObjectId(id)
    })

    response.status(200).json(tareaActualizada)
}))

// DELETE: eliminar una tarea por ID

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
 *         description: Identificador de la tarea
 *     responses:
 *       200:
 *         description: Tarea eliminada
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/MessageResponse'
 *       400:
 *         description: ID no válido
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/MessageResponse'
 *       401:
 *         description: Token requerido
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/MessageResponse'
 *       403:
 *         description: Token inválido o caducado
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/MessageResponse'
 *       404:
 *         description: Tarea no encontrada
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/MessageResponse'
 */

app.delete('/api/tareas/:id', verifyToken, asyncHandler(async (request, response) => {
    const { id } = request.params

    if (!ObjectId.isValid(id)) {
        return response.status(400).json({
            message: 'ID no válido'
        })
    }

    const database = client.db(DB_NAME)
    const collection = database.collection(TASKS)

    const results = await collection.deleteOne({
        _id: new ObjectId(id)
    })

    if (results.deletedCount === 0) {
        return response.status(404).json({
            message: 'Tarea no encontrada'
        })
    }

    response.status(200).json({
        message: 'Tarea eliminada correctamente',
        ...results
    })
}))

// Manejador de errores: respuestas limpias en vez de peticiones colgadas
app.use((error, request, response, next) => {
    if (error.type === 'entity.parse.failed') {
        return response.status(400).json({ message: 'JSON no válido' })
    }
    console.error(error)
    response.status(500).json({ message: 'Error del servidor' })
})

if (!process.env.VERCEL) {
    app.listen(PORT, () => {
        console.log(`Servidor web iniciado en puerto: ${PORT}`)
    })
}

export default app

