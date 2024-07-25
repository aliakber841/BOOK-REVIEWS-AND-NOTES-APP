CREATE TABLE users(
    id serial primary key,
    username varchar(100) NOT NULL,
    email varchar(100) NOT NULL UNIQUE,
    password varchar(100) NOT NULL
);

CREATE TABLE user_data(
   booktitle varchar(100),
   bookauthor varchar(100),
   bookimage varchar(100),
   rating int,
   readdate date,
   notes text,
   review text,
   isbn varchar(30),
   user_email varchar(100) REFERENCES users(email)
    PRIMARY KEY (user_email, isbn)
);