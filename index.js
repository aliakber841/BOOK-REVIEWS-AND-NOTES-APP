import express from "express";
import axios from "axios";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import {Strategy} from "passport-local";
import session from "express-session";
import env from "dotenv";
import GoogleStrategy from "passport-google-oauth2";


const app=express();
const port=3000;
const saltRounds=10;
env.config();

app.use(
    session({
      secret: process.env.SESSION_SECRET,
      resave: false,
      saveUninitialized: true,
    })
  );

  app.use(bodyParser.urlencoded({extended:true}));
app.use(express.static("public"));

app.use(passport.initialize());
app.use(passport.session());

const db= new pg.Client({
    user: process.env.PG_USER,
    host: process.env.PG_HOST,
    database: process.env.PG_DATABASE,
    password: process.env.PG_PASSWORD,
    port: process.env.PG_PORT,
}
)
db.connect();


app.get("/",(req,res)=>{
    res.render("index.ejs")
})

app.get("/register",(req,res)=>{
    res.render("register.ejs")
})

app.get("/login",(req,res)=>{
    res.render("login.ejs")
})

app.get("/bookdetail",(req,res)=>{
  res.render("bookdetail.ejs")
})

 

app.get("/booknotes/:isbn", async (req, res) => {
  const defaultImage = '/images/no-image.png';
  if (req.isAuthenticated()) {
    const bookisbn = req.params.isbn;
    console.log("ISBN from params:", bookisbn);

    if (!bookisbn) {
      return res.status(400).send("ISBN is required");
    }

    try {
      const result = await db.query(
        "SELECT * FROM user_data WHERE user_email=$1 AND isbn=$2",
        [req.user.email, bookisbn]
      );

      console.log("Database query result:", result.rows);

      if (result.rows.length > 0) {
        const bookData = result.rows[0];
        const bookDetail = {
          bookisbn: bookData.isbn,
          booktitle: bookData.booktitle,
          bookauthor: bookData.bookauthor,
          bookimage: bookData.bookimage && bookData.bookimage.startsWith('http') ? bookData.bookimage : defaultImage,
          readdate: bookData.readdate,
          rating: bookData.rating,
          review: bookData.review,
          notes: bookData.notes,
        };

        res.render("book-notes.ejs", {
          book: bookDetail
        });
      } else {
        console.log("No book found for the given ISBN and user email.");
        res.status(404).send("Book not found");
      }
    } catch (err) {
      console.error("Database query error:", err);
      res.status(500).send("Internal server error");
    }
  } else {
    res.redirect("/login");
  }
});



app.get("/home",async (req,res)=>{
    if (req.isAuthenticated()) {
      const userBooks = await db.query("SELECT * FROM user_data WHERE user_email = $1", [req.user.email]);

      const books = userBooks.rows.map(row => ({
        bookisbn:row.isbn,
        booktitle: row.booktitle,
        bookauthor: row.bookauthor,
        bookimage: row.bookimage,
        readdate: row.readdate,
        rating: row.rating,
        review: row.review,
        notes: row.notes,
      }));
        res.render("home.ejs",{
          name: req.user.username,
          books:books
        });
      } else {
        res.redirect("/login");
      }
})

app.post("/bookdetail", async (req, res) => {
  if (req.isAuthenticated()) {
    try {
      const { isbn, date, bookReview, bookNotes, rating, bookauthor } = req.body;
      const existingBook = await db.query(
        "SELECT * FROM user_data WHERE user_email = $1 AND isbn = $2",
        [req.user.email, isbn]
      );

      if (existingBook.rows.length > 0) {
        return res.status(400).json({ message: 'Book already added to the database.' });
      }
      const bookResponse = await axios.get(`https://openlibrary.org/isbn/${isbn}.json`);
      const bookData = bookResponse.data;

      const coverUrl = `https://covers.openlibrary.org/b/isbn/${isbn}-M.jpg?default=false`;
      await db.query(
        "INSERT INTO user_data (isbn, booktitle, bookauthor, bookimage, readdate, rating, review, notes, user_email) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        [isbn, bookData.title, bookauthor, coverUrl, date, rating, bookReview, bookNotes, req.user.email]
      );
      const userBooks = await db.query(
        "SELECT * FROM user_data WHERE user_email = $1",
        [req.user.email]
      );

      const books = userBooks.rows.map(row => ({
        bookisbn: row.isbn,
        booktitle: row.booktitle,
        bookauthor: row.bookauthor,
        bookimage: row.bookimage,
        readdate: row.readdate,
        rating: row.rating,
        review: row.review,
        notes: row.notes,
      }));

      res.render("home.ejs", {
        name: req.user.username,
        books: books,
      });

    } catch (err) {
      console.error(err);
      res.status(400).json({ error: 'Invalid ISBN or book not found.' });
    }
  } else {
    res.status(401).json({ error: 'Unauthorized' });
  }
});


app.post("/delete/:isbn",async(req,res)=>{
  if (req.isAuthenticated()) {
    const bookisbn = req.params.isbn;
    console.log("ISBN from params:", bookisbn);

    const result = await db.query("Delete from user_data where user_email=$1 and isbn=$2",[
      req.user.email,bookisbn
    ])

    console.log(result);
      res.redirect("/home");
  }
})

app.get('/edit/:isbn', async (req, res) => {
  if (req.isAuthenticated()) {
    const bookisbn = req.params.isbn;
    try {
      const result = await db.query("SELECT * FROM user_data WHERE user_email = $1 AND isbn = $2", [
        req.user.email, bookisbn
      ]);

      if (result.rows.length > 0) {
        const book = result.rows[0];
        console.log(book)
        res.render('edit-book.ejs', { book });
      } else {
        res.status(404).send("Book not found.");
      }
    } catch (err) {
      console.error(err);
      res.status(500).send("Error retrieving book details.");
    }
  } else {
    res.status(401).send("Unauthorized");
  }
});

app.post('/edit/:isbn', async (req, res) => {
  if (req.isAuthenticated()) {
    const bookisbn = req.params.isbn;
    const { edit_bookauthor, edit_rating, edit_review, edit_notes } = req.body;

    try {
      const currentResult = await db.query(
        "SELECT bookauthor, rating, review, notes FROM user_data WHERE user_email = $1 AND isbn = $2",
        [req.user.email, bookisbn]
      );

      if (currentResult.rows.length === 0) {
        return res.status(404).send("Book not found.");
      }
      const currentData = currentResult.rows[0];
      console.log("Current Data:", currentData);
      console.log("New Data from Form:", { edit_bookauthor, edit_rating, edit_review, edit_notes });
      const newBookauthor = edit_bookauthor || currentData.bookauthor;
      const newRating = edit_rating || currentData.rating;
      const newReview = edit_review || currentData.review;
      const newNotes = edit_notes || currentData.notes;

      console.log("Final Data to be Updated:", {
        newBookauthor, newRating, newReview, newNotes
      });
  
      const result = await db.query(
        "UPDATE user_data SET bookauthor = $1, rating = $2, review = $3, notes = $4 WHERE user_email = $5 AND isbn = $6",
        [newBookauthor, newRating, newReview, newNotes, req.user.email, bookisbn]
      );

      if (result.rowCount > 0) {
        res.redirect('/home');
      } else {
        res.status(404).send("Book not found or update failed.");
      }
    } catch (err) {
      console.error(err);
      res.status(500).send("Error updating book details.");
    }
  } else {
    res.redirect('/login');
  }
});


app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

app.get(
  "/auth/google/home",
  passport.authenticate("google", {
    successRedirect: "/home",
    failureRedirect: "/login",
  })
);

app.post(
    "/login",
    passport.authenticate("local", {
      successRedirect: "/home",
      failureRedirect: "/login",
    })
  );

app.post("/register",async(req,res)=>{
  const username=req.body.username;
    const email=req.body.email;
    const password=req.body.password;
   try{
    const checkResult=await db.query("Select * from users where email=$1",[email]);
    if(checkResult.rows.length>0){
        res.redirect("/login");
    } else{
        bcrypt.hash(password,saltRounds,async(err,hash)=>{
            if(err){
                console.error("Error hashing password",err)
            } else{
                const result= await db.query("Insert into users (username,email,password) values ($1,$2,$3) RETURNING *",
                    [username,email,hash]
                );
                const user=result.rows[0];
                req.login(user,(err)=>{
                    console.log("success");
                    res.redirect("/home");
                })
            }
        })
    }

   } catch(err){
    console.log(err);
   }
})

passport.use( "local",
    new Strategy(async function verify(username, password, cb) {
      try {
        const result = await db.query("SELECT * FROM users WHERE email = $1 ", [
          username,
        ]);
        if (result.rows.length > 0) {
          const user = result.rows[0];
          const storedHashedPassword = user.password;
          console.log(user);
          bcrypt.compare(password, storedHashedPassword, (err, valid) => {
            if (err) {
              //Error with password check
              console.error("Error comparing passwords:", err);
              return cb(err);
            } else {
              if (valid) {
                //Passed password check
                return cb(null, user);
              } else {
                //Did not pass password check
                return cb(null, false);
              }
            }
          });
        } else {
          return cb("User not found");
        }
      } catch (err) {
        console.log(err);
      }
    })
  );

  passport.use("google",
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: "http://localhost:3000/auth/google/home",
        userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
      }, async function verify(accessToken,refreshToken,profile,cb){
        try{
          console.log(profile);
          const result=await db.query("Select * from users where email=$1",[profile.email]);
          if(result.rows.length===0){
            const newUser= await db.query("Insert into users (username,email,password) values ($1,$2,$3) RETURNING *",
              [profile.displayName,profile.email,"google"]
            )
            return cb(newUser.rows[0]);
          }else{
            return cb(null,result.rows[0])
          }
        } catch(err){
          console.log(err);
        }
        }
    )
  )

passport.serializeUser((user, cb) => {
    cb(null, user);
  });
  
  passport.deserializeUser((user, cb) => {
    cb(null, user);
  });

app.listen(port,()=>{
    console.log(`Listening on port ${port}`)
})
