
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

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 5,
    message: {
        error: 'Demasiados intentos de inicio de sesión. Inténtalo de nuevo dentro de 15 minutos.'
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
        components: { securitySchemes: {
                bearerAuth: {
                    type: 'http',
                    scheme: 'bearer',
                    bearerFormat: 'JWT'
                }
            } }
    },
    apis: [path.join(process.cwd(), 'index.js')]
}

const swaggerSpec = swaggerJsdoc(swaggerOptions)


app.use(express.json())
app.use(cors())

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

// Página inicial
app.get("/", (request, response) => {
    response.redirect("/api/tareas")
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
 */

app.get('/api/usuarios', async (request, response) => {
    const database = client.db(DB_NAME)
    const collection = database.collection(USERS)

    const results = await collection.find({}).toArray()

    response.status(200).json(results)
})

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
 *       400:
 *         description: Datos obligatorios no proporcionados
 *       409:
 *         description: El usuario o email ya existe
 */

  
app.post('/api/usuarios', async (request, response) => {
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
})


// GET: obtener un usuario por ID



app.get('/api/usuarios/:id', async (request, response) => {
    const database = client.db(DB_NAME)
    const collection = database.collection(USERS)

    const { id } = request.params

    if (!ObjectId.isValid(id)) {
        return response.status(400).json({
            message: 'ID no válido'
        })
    }

    const result = await collection.findOne({
        _id: new ObjectId(id)
    })

    if (!result) {
        return response.status(404).json({
            message: 'Usuario no encontrado'
        })
    }

    response.status(200).json(result)
})

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
 *       404:
 *         description: Usuario no encontrado
 */

app.put('/api/usuarios/:id', async (request, response) => {
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
})

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
 *       404:
 *         description: Usuario no encontrado
 */

app.delete('/api/usuarios/:id', async (request, response) => {
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
})

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
 */

app.get('/api/tareas', async (request, response) => {
    const database = client.db(DB_NAME)
    const collection = database.collection(TASKS)

    const results = await collection.find({}).toArray()

    response.status(200).json(results)
})

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
 *             type: object
 *             required:
 *               - titulo
 *             properties:
 *               titulo:
 *                 type: string
 *                 example: Estudiar para el examen
 *               descripcion:
 *                 type: string
 *                 example: Repasar REST y JWT
 *               completada:
 *                 type: boolean
 *                 example: false
 *               fechaLimite:
 *                 type: string
 *                 nullable: true
 *                 example: "2026-10-20"
 *     responses:
 *       201:
 *         description: Tarea creada
 *       401:
 *         description: Token requerido
 *       403:
 *         description: Token inválido o caducado
 */

app.post('/api/tareas', verifyToken, async (request, response) => {
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
})

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
 *             type: object
 *             required:
 *               - email
 *               - password
 *             properties:
 *               email:
 *                 type: string
 *                 example: prueba@gmail.com
 *               password:
 *                 type: string
 *                 example: Prueba123
 *     responses:
 *       200:
 *         description: Inicio de sesión correcto
 *       400:
 *         description: Faltan datos o el JSON no es válido
 *       401:
 *         description: Credenciales incorrectas
 *       429:
 *         description: Demasiados intentos de inicio de sesión
 */


app.post('/api/login', loginLimiter, async (request, response) => {
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
 *             required:
 *               - refreshToken
 *             properties:
 *               refreshToken:
 *                 type: string
 *                 description: Refresh token obtenido al iniciar sesión.
 *     responses:
 *       200:
 *         description: Access token renovado correctamente
 *       400:
 *         description: Falta el refresh token
 *       401:
 *         description: Refresh token inválido o caducado
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
 *       400:
 *         description: ID no válido
 *       404:
 *         description: Tarea no encontrada
 */

app.get('/api/tareas/:id', async (request, response) => {
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
})

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
 *       400:
 *         description: Datos o ID no válidos
 *       401:
 *         description: Token requerido
 *       403:
 *         description: Token inválido o caducado
 *       404:
 *         description: Tarea no encontrada
 */

app.put('/api/tareas/:id', verifyToken, async (request, response) => {
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
})

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
})

if (!process.env.VERCEL) {
    app.listen(PORT, () => {
        console.log(`Servidor web iniciado en puerto: ${PORT}`)
    })
}

export default app

