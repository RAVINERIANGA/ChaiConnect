let mysql=require('mysql');
let connection =  mysql.createConnection({
    host:"localhost",
    user:"root",
    password:"DBSB3272",
    database: "chaiconnect"
});
connection.connect(function(err){
    if(err) throw err;
    console.log("Connected to the database successfully");
});