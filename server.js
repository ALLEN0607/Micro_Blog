const express = require('express');
const expressHandlebars = require('express-handlebars');
const session = require('express-session');
const canvas = require('canvas');
const sqlite = require('sqlite');
const sqlite3 = require('sqlite3');
const moment = require('moment');
const path = require('path');
const dotenv = require('dotenv');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Configuration and Setup
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

// Load environment variables from .env file
dotenv.config();

const app = express();
const PORT = 3000;

const sessionSecret = process.env.SESSION_SECRET || 'defaultsecret';
const dbFileName = process.env.DB_FILE || 'default.db';



/*
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    Handlebars Helpers

    Handlebars helpers are custom functions that can be used within the templates 
    to perform specific tasks. They enhance the functionality of templates and 
    help simplify data manipulation directly within the view files.

    In this project, two helpers are provided:
    
    1. toLowerCase:
       - Converts a given string to lowercase.
       - Usage example: {{toLowerCase 'SAMPLE STRING'}} -> 'sample string'

    2. ifCond:
       - Compares two values for equality and returns a block of content based on 
         the comparison result.
       - Usage example: 
            {{#ifCond value1 value2}}
                <!-- Content if value1 equals value2 -->
            {{else}}
                <!-- Content if value1 does not equal value2 -->
            {{/ifCond}}
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
*/

// Set up Handlebars view engine with custom helpers
//
app.engine('handlebars', expressHandlebars.engine({
    helpers: {
        toLowerCase: function (str) {
            return str.toLowerCase();
        },
        ifCond: function (v1, v2, options) {
            if (v1 === v2) {
                return options.fn(this);
            }
            return options.inverse(this);
        },
        formatDate: function (date) {
            return moment(date).format('MMMM Do YYYY, h:mm:ss a');
        }
    },
    defaultLayout: 'main'
}));

app.set('view engine', 'handlebars');
app.set('views', './views');

//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Middleware
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

app.use(
    session({
        secret: 'oneringtorulethemall',     // Secret key to sign the session ID cookie
        resave: false,                      // Don't save session if unmodified
        saveUninitialized: false,           // Don't create session until something stored
        cookie: { secure: false },          // True if using https. Set to false for development without https
    })
);

// Replace any of these variables below with constants for your application. These variables
// should be used in your template files. 
// 
app.use((req, res, next) => {
    res.locals.appName = 'MicroBlog';
    res.locals.copyrightYear = 2024;
    res.locals.postNeoType = 'Post';
    res.locals.loggedIn = req.session.loggedIn || false;
    res.locals.userId = req.session.userId || '';
    next();
});

app.use(express.static('public'));                  // Serve static files
app.use(express.urlencoded({ extended: true }));    // Parse URL-encoded bodies (as sent by HTML forms)
app.use(express.json());                            // Parse JSON bodies (as sent by API clients)

app.use((req, res, next) => {
    console.log('Session info:', req.session);
    next();
});

let db;

async function initializeDB() {
    db = await sqlite.open({ filename: dbFileName, driver: sqlite3.Database });
    console.log('Database connection established.');
}

initializeDB().catch(err => {
    console.error('Error initializing database:', err);
});

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/callback"
  },
  async function(accessToken, refreshToken, profile, done) {
    let user = await db.get('SELECT * FROM users WHERE hashedGoogleId = ?', [profile.id]);
    if (!user) {
      await db.run('INSERT INTO users (username, hashedGoogleId, avatar_url, memberSince) VALUES (?, ?, ?, ?)', [
        profile.displayName,
        profile.id,
        profile.photos[0].value,
        new Date().toISOString(),
      ]);
      user = await db.get('SELECT * FROM users WHERE hashedGoogleId = ?', [profile.id]);
    }
    return done(null, user);
  }
));

passport.serializeUser((user, done) => {
    done(null, user.id);
  });
  
  passport.deserializeUser(async (id, done) => {
    const user = await db.get('SELECT * FROM users WHERE id = ?', [id]);
    done(null, user);
  });
  
  app.use(passport.initialize());
  app.use(passport.session());

//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Routes
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

// Home route: render home view with posts and user
// We pass the posts and user variables into the home
// template
// Google Login
// Route to start the OAuth flow
app.get('/auth/google', passport.authenticate('google', { scope: ['profile'] }));

// OAuth callback route
app.get('/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => {
    req.session.userId = req.user.id;
    req.session.loggedIn = true;
    res.redirect('/');
  }
);

// Logout route
app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.redirect('/error');
    }
    res.redirect('/');
  });
});


app.get('/', async (req, res) => {
    try {
        const posts = await db.all('SELECT * FROM posts ORDER BY timestamp DESC');
        const postsWithComments = await Promise.all(posts.map(async post => {
            const comments = await db.all('SELECT * FROM comments WHERE postId = ? ORDER BY timestamp ASC', [post.id]);
            return { ...post, comments };
        }));
        const user = await getCurrentUser(req) || {};
        res.render('home', { posts: postsWithComments, user });
    } catch (err) {
        console.error('Error fetching posts:', err);
        res.status(500).send('Internal Server Error');
    }
});
// Register GET route is used for error response from registration
//
app.get('/register', (req, res) => {
    res.render('loginRegister', { regError: req.query.error });
});

// Login route GET route is used for error response from login
//
app.get('/login', (req, res) => {
    res.render('loginRegister', { loginError: req.query.error });
});

// Error route: render error page
//
app.get('/error', (req, res) => {
    res.render('error');
});

// Additional routes that you must implement


app.get('/post/:id', async (req, res) => {
    const post = await db.get('SELECT * FROM posts WHERE id = ?', [req.params.id]);
    if (post) {
        res.render('postDetail', { post });
    } else {
        res.redirect('/error');
    }
});

// Post creation route
app.post('/posts', isAuthenticated, async (req, res) => {
    try {
        const { title, content } = req.body;
        const user = await getCurrentUser(req);

        if (!user) {
            return res.redirect('/login');
        }

        await addPost(title, content, user);
        res.redirect('/');
    } catch (err) {
        console.error('Error creating post:', err);
        res.status(500).send('Internal Server Error');
    }
});

// Like a post
app.post('/like/:id', isAuthenticated, async (req, res) => {
    try {
        const postId = req.params.id;
        const user = await getCurrentUser(req);
        const post = await db.get('SELECT * FROM posts WHERE id = ?', [postId]);
        if (post && post.username !== user.username) {
            await db.run('UPDATE posts SET likes = likes + 1 WHERE id = ?', [postId]);
            const updatedPost = await db.get('SELECT * FROM posts WHERE id = ?', [postId]);
            res.json({ likes: updatedPost.likes });
        } else {
            res.json({ error: 'Cannot like your own post' });
        }
    } catch (err) {
        console.error('Error liking post:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


// Profile
app.get('/profile', isAuthenticated, async (req, res) => {
    const user = await getCurrentUser(req);
    const userPosts = await db.all('SELECT * FROM posts WHERE username = ? ORDER BY timestamp DESC', [user.username]);
    const favoritePosts = await db.all('SELECT posts.* FROM posts JOIN favorites ON posts.id = favorites.postId WHERE favorites.username = ?', [user.username]);
    res.render('profile', { user, posts: userPosts, favorites: favoritePosts });
});

app.get('/avatar/:username', async (req, res) => {
    const username = req.params.username;
    const avatar = generateAvatar(username[0]);
    res.setHeader('Content-Type', 'image/png');
    res.send(avatar);
});

const { v4: uuidv4 } = require('uuid');

app.post('/register', async (req, res) => {
    const { username } = req.body;
    const existingUser = await db.get('SELECT * FROM users WHERE username = ?', [username]);
    if (existingUser) {
        console.log('Registration failed: Username already exists');
        return res.redirect('/register?error=Username already exists');
    }

    // Generate a unique value for hashedGoogleId
    const hashedGoogleId = uuidv4();

    try {
        await db.run('INSERT INTO users (username, hashedGoogleId, avatar_url, memberSince) VALUES (?, ?, ?, ?)', [
            username,
            hashedGoogleId,
            '',
            new Date().toISOString(),
        ]);
        const user = await db.get('SELECT * FROM users WHERE username = ?', [username]);
        req.session.userId = user.id;
        req.session.loggedIn = true;
        console.log('User registered and logged in:', user);
        res.redirect('/');
    } catch (error) {
        console.error('Error registering user:', error);
        res.redirect('/register?error=Registration failed');
    }
});


app.post('/login', async (req, res) => {
    const { username } = req.body;
    const user = await db.get('SELECT * FROM users WHERE username = ?', [username]);
    if (!user) {
        console.log('Login failed: Invalid username');
        return res.redirect('/login?error=Invalid username');
    }
    req.session.userId = user.id;
    req.session.loggedIn = true;
    console.log('User logged in:', user);
    res.redirect('/');
});


app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.redirect('/error');
        }
        res.redirect('/');
    });
});

// Delete a post
app.post('/delete/:id', isAuthenticated, async (req, res) => {
    try {
        const postId = req.params.id;
        const user = await getCurrentUser(req);
        const success = await deletePost(postId, user.id);
        if (success) {
            res.json({ success: true });
        } else {
            res.json({ error: 'You can only delete your own posts' });
        }
    } catch (err) {
        console.error('Error deleting post:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Add a comment
app.post('/comment/:id', isAuthenticated, async (req, res) => {
    const postId = req.params.id;
    const user = await getCurrentUser(req);
    const { content } = req.body;

    try {
        await db.run('INSERT INTO comments (postId, username, content, timestamp) VALUES (?, ?, ?, ?)', [
            postId, user.username, content, new Date().toISOString()
        ]);
        res.redirect('/');
    } catch (err) {
        console.error('Error adding comment:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Update Home_page
app.get('/', async (req, res) => {
    try {
        const posts = await db.all('SELECT * FROM posts ORDER BY timestamp DESC');
        const postsWithComments = await Promise.all(posts.map(async post => {
            const comments = await db.all('SELECT * FROM comments WHERE postId = ? ORDER BY timestamp ASC', [post.id]);
            return { ...post, comments };
        }));
        const user = await getCurrentUser(req) || {};
        res.render('home', { posts: postsWithComments, user });
    } catch (err) {
        console.error('Error fetching posts:', err);
        res.status(500).send('Internal Server Error');
    }
});

// 获取帖子及其评论
async function getPostWithComments(postId) {
    const post = await db.get('SELECT * FROM posts WHERE id = ?', [postId]);
    const comments = await db.all('SELECT * FROM comments WHERE postId = ? ORDER BY timestamp ASC', [postId]);
    return { ...post, comments };
}

// Add to favorites
app.post('/favorite/:id', isAuthenticated, async (req, res) => {
    const postId = req.params.id;
    const user = await getCurrentUser(req);

    try {
        // 检查用户是否已经收藏了该帖子
        const existingFavorite = await db.get('SELECT * FROM favorites WHERE postId = ? AND username = ?', [postId, user.username]);
        if (existingFavorite) {
            return res.json({ error: 'You have already favorited this post' });
        }

        // 如果没有收藏则插入新记录
        await db.run('INSERT INTO favorites (postId, username) VALUES (?, ?)', [postId, user.username]);
        res.json({ success: true });
    } catch (err) {
        console.error('Error adding favorite:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


// Get user's favorites
app.get('/favorites', isAuthenticated, async (req, res) => {
    const user = await getCurrentUser(req);
    const favoritePosts = await db.all('SELECT posts.* FROM posts JOIN favorites ON posts.id = favorites.postId WHERE favorites.username = ?', [user.username]);

    res.render('favorites', { user, posts: favoritePosts });
});


//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Server Activation
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});

//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Support Functions and Variables
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

// Function to find a user by username
function findUserByUsername(username) {
    // TODO: Return user object if found, otherwise return undefined
    return users.find(user => user.username === username);
}

// Function to find a user by user ID
function findUserById(userId) {
    // TODO: Return user object if found, otherwise return undefined
    return users.find(user => user.id === userId);
}

// Function to add a new user
function addUser(username) {
    // TODO: Create a new user object and add to users array
    const newUser = {
        id: users.length + 1,
        username,
        avatar_url: undefined,
        memberSince: new Date().toISOString()
    };
    users.push(newUser);
}

// Middleware to check if user is authenticated
function isAuthenticated(req, res, next) {
    console.log('Session info:', req.session);
    if (req.session.userId && req.session.loggedIn) {
        console.log('User is authenticated:', req.session.userId);
        return next();
    }
    console.log('User is not authenticated');
    res.redirect('/login');
}

// Function to register a user
async function registerUser(req, res) {
    const { username } = req.body;
    const existingUser = await db.get('SELECT * FROM users WHERE username = ?', [username]);
    if (existingUser) {
        console.log('Registration failed: Username already exists');
        return res.redirect('/register?error=Username already exists');
    }
    try {
        await db.run('INSERT INTO users (username, hashedGoogleId, avatar_url, memberSince) VALUES (?, ?, ?, ?)', [
            username,
            '', // Provide a unique value or handle Google ID
            '',
            new Date().toISOString(),
        ]);
        const user = await db.get('SELECT * FROM users WHERE username = ?', [username]);
        req.session.userId = user.id;
        req.session.loggedIn = true;
        console.log('User registered and logged in:', user);
        res.redirect('/');
    } catch (error) {
        console.error('Error registering user:', error);
        res.redirect('/register?error=Registration failed');
    }
}


// Function to login a user
function loginUser(req, res) {
    // TODO: Login a user and redirect appropriately
    const { username } = req.body;
    const user = findUserByUsername(username);
    if (!user) {
        return res.redirect('/login?error=Invalid username');
    }
    req.session.userId = user.id;
    req.session.loggedIn = true;
    res.redirect('/');
}

// Function to logout a user
function logoutUser(req, res) {
    // TODO: Destroy session and redirect appropriately
    req.session.destroy(err => {
        if (err) {
            return res.redirect('/error');
        }
        res.redirect('/');
    });
}

// Function to render the profile page
function renderProfile(req, res) {
    // TODO: Fetch user posts and render the profile page
    const user = getCurrentUser(req);
    const userPosts = posts.filter(post => post.username === user.username);
    res.render('profile', { user, posts: userPosts });
}

// Function to update post likes
// function updatePostLikes(postId, userId) {
//     const post = posts.find(post => post.id === parseInt(postId));
//     if (post && post.username !== findUserById(userId).username) {
//         post.likes += 1;
//     }
//     return post;
// }

// Function to handle avatar generation and serving
function handleAvatar(req, res) {
    // TODO: Generate and serve the user's avatar image
    const username = req.params.username;
    const avatar = generateAvatar(username[0]);
    res.setHeader('Content-Type', 'image/png');
    res.send(avatar);
}

// Function to get the current user from session
async function getCurrentUser(req) {
    if (!req.session.userId) {
        console.log('No userId in session');
        return null;
    }
    try {
        console.log('Fetching user for userId:', req.session.userId);
        const user = await db.get('SELECT * FROM users WHERE id = ?', [req.session.userId]);
        if (!user) {
            console.log('No user found for userId:', req.session.userId);
        } else {
            console.log('User found:', user);
        }
        return user;
    } catch (error) {
        console.error('Error fetching user from database:', error);
        return null;
    }
}

async function getPostComments(postId) {
    const comments = await db.all('SELECT * FROM comments WHERE postId = ? ORDER BY timestamp DESC', [postId]);
    return comments;
}

// Function to get all posts, sorted by latest first
async function getPosts() {
    const posts = await db.all('SELECT * FROM posts ORDER BY timestamp DESC');
    return posts;
}

// Function to add a new post
async function addPost(title, content, user) {
    try {
        await db.run(
            'INSERT INTO posts (title, content, username, timestamp, likes) VALUES (?, ?, ?, ?, ?)',
            [title, content, user.username, new Date().toISOString(), 0]
        );
        console.log('Post added to database');
    } catch (err) {
        console.error('Error adding post to database:', err);
        throw err;
    }
}

async function deletePost(postId, userId) {
    const post = await db.get('SELECT * FROM posts WHERE id = ?', [postId]);
    if (post && post.username === userId) {
        await db.run('DELETE FROM posts WHERE id = ?', [postId]);
        return true;
    }
    return false;
}




// Function to generate an image avatar
function generateAvatar(letter, width = 100, height = 100) {
    // TODO: Generate an avatar image with a letter
    // Steps:
    // 1. Choose a color scheme based on the letter
    // 2. Create a canvas with the specified width and height
    // 3. Draw the background color
    // 4. Draw the letter in the center
    // 5. Return the avatar as a PNG buffer
    
    const Canvas = canvas.Canvas;
    const ctx = new Canvas(width, height);
    const context = ctx.getContext('2d');

    const color = '#' + Math.floor(Math.random() * 16777215).toString(16);
    context.fillStyle = color;
    context.fillRect(0, 0, width, height);

    context.font = 'bold 50px Arial';
    context.fillStyle = '#FFF';
    context.textAlign = 'center';
    context.textBaseline = 'middle';
    context.fillText(letter.toUpperCase(), width / 2, height / 2);

    return ctx.toBuffer();
}