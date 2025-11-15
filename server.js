// =========================
// Online Sports Network Backend
// Node.js + Express + MySQL + JWT + bcrypt
// =========================

const express = require("express");
const mysql = require("mysql2/promise");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const path = require("path");




const app = express();
app.use(cors());
app.use(express.json());



// ================= MySQL Connection =================
const db = mysql.createPool({
    host: "localhost",
    user: "root",
    password: "neha123",
    database: "osn_db",
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// ================= JWT Secret =================
const JWT_SECRET = "osn_secret_123";

// ================= Middleware =================
const authMiddleware = role => async (req,res,next)=>{
    const token = req.headers.authorization?.split(" ")[1];
    if(!token) return res.status(401).json({message:"Unauthorized"});
    try{
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        if(role && decoded.role!==role) return res.status(403).json({message:"Forbidden"});
        next();
    }catch(err){
        return res.status(401).json({message:"Invalid Token"});
    }
};

// ================= Serve Frontend =================
app.use(express.static(path.join(__dirname,"public")));

app.get("/", (req,res)=>{
    res.sendFile(path.join(__dirname,"public/index.html"));
});

// ================= AUTH =================
app.post("/api/auth/register", async(req,res)=>{
    const {name,email,password,role} = req.body;
    if(!name||!email||!password||!role) return res.status(400).json({message:"Fill all fields"});
    try{
        const [existing] = await db.query("SELECT * FROM users WHERE email=?",[email]);
        if(existing.length>0) return res.status(400).json({message:"Email already exists"});
        const hashed = await bcrypt.hash(password,8);
        const [result] = await db.query("INSERT INTO users (name,email,password,role,created_at) VALUES (?,?,?,?,NOW())",[name,email,hashed,role]);
        const user = {id:result.insertId,name,email,role};
        const token = jwt.sign(user, JWT_SECRET,{expiresIn:"7d"});
        res.json({user,token});
    }catch(err){ console.log(err); res.status(500).json({message:"Server error"}) }
});

app.post("/api/auth/login", async(req,res)=>{
    const {email,password} = req.body;
    if(!email||!password) return res.status(400).json({message:"Fill all fields"});
    try{
        const [users] = await db.query("SELECT * FROM users WHERE email=?",[email]);
        if(users.length===0) return res.status(400).json({message:"Invalid email"});
        const user = users[0];
        const match = await bcrypt.compare(password,user.password);
        if(!match) return res.status(400).json({message:"Invalid password"});
        const payload = {id:user.id,name:user.name,email:user.email,role:user.role};
        const token = jwt.sign(payload,JWT_SECRET,{expiresIn:"7d"});
        res.json({user:payload,token});
    }catch(err){ console.log(err); res.status(500).json({message:"Server error"}) }
});

// ================= USER APIs =================
app.get("/api/user/profile/:id", authMiddleware("user"), async(req,res)=>{
    const {id} = req.params;
    const [rows] = await db.query("SELECT id,name,email,phone,city,age FROM users WHERE id=? AND role='user'",[id]);
    res.json(rows[0]||{});
});

app.put("/api/user/update/:id", authMiddleware("user"), async(req,res)=>{
    const {id} = req.params;
    const {name,email,phone,city,age} = req.body;
    await db.query("UPDATE users SET name=?,email=?,phone=?,city=?,age=? WHERE id=? AND role='user'",[name,email,phone,city,age,id]);
    res.json({message:"Profile updated"});
});

app.put("/api/user/password/:id", authMiddleware("user"), async(req,res)=>{
    const {id} = req.params;
    const {name,email,phone,city,age} = req.body;
    const hashed = await bcrypt.hash(password,8);
    await db.query("UPDATE users SET password=? WHERE id=? AND role='user'",[hashed,id]);
    res.json({message:"Password updated"});
});

app.get("/api/user/tournaments", authMiddleware("user"), async(req,res)=>{
    const [rows] = await db.query("SELECT * FROM tournaments");
    res.json(rows);
});

// ================= PLAYER APIs =================
app.get("/api/player/stats/:id", authMiddleware("player"), async(req,res)=>{
    const {id} = req.params;
    const [stats] = await db.query("SELECT * FROM player_stats WHERE player_id=?",[id]);
    res.json(stats[0]||{matches:0,wins:0,losses:0,points:0,history:[]});
});

app.get("/api/player/matches/:id", authMiddleware("player"), async(req,res)=>{
    const {id} = req.params;
    const [matches] = await db.query("SELECT * FROM matches WHERE player_id=?",[id]);
    res.json(matches);
});

app.get("/api/player/training/:id", authMiddleware("player"), async(req,res)=>{
    const {id} = req.params;
    const [training] = await db.query("SELECT * FROM training WHERE player_id=?",[id]);
    res.json(training);
});

app.get("/api/player/achievements/:id", authMiddleware("player"), async(req,res)=>{
    const {id} = req.params;
    const [achievements] = await db.query("SELECT * FROM achievements WHERE player_id=?",[id]);
    res.json(achievements);
});

app.put("/api/player/update/:id", authMiddleware("player"), async(req,res)=>{
    const {id} = req.params;
    const {name,email,phone,city,age} = req.body;
    await db.query("UPDATE users SET name=?,email=?,phone=?,city=?,age=? WHERE id=? AND role='player'",
        [name,email,phone,city,age,id]);
    res.json({message:"Profile updated"});
});

app.put("/api/player/password/:id", authMiddleware("player"), async(req,res)=>{
    const {id} = req.params;
    const {password} = req.body;
    const hashed = await bcrypt.hash(password,8);
    await db.query("UPDATE users SET password=? WHERE id=? AND role='player'",[hashed,id]);
    res.json({message:"Password updated"});
});

// ================= COACH APIs =================
app.get("/api/coach/dashboard/:id", authMiddleware("coach"), async(req,res)=>{
    const {id} = req.params;
    const [teams] = await db.query("SELECT * FROM teams WHERE coach_id=?",[id]);
    res.json({teams});
});

app.get("/api/coach/teams/:id", authMiddleware("coach"), async(req,res)=>{
    const {id} = req.params;
    const [teams] = await db.query("SELECT * FROM teams WHERE coach_id=?",[id]);
    for(const t of teams){
        const [members] = await db.query("SELECT id,name FROM users WHERE team_id=?",[t.id]);
        t.members = members;
    }
    res.json(teams);
});

app.post("/api/coach/team/remove-player", authMiddleware("coach"), async(req,res)=>{
    const {team_id,player_id} = req.body;
    await db.query("UPDATE users SET team_id=NULL WHERE id=? AND role='player'",[player_id]);
    res.json({message:"Player removed"});
});

app.get("/api/coach/training/:id", authMiddleware("coach"), async(req,res)=>{
    const [training] = await db.query("SELECT * FROM training WHERE coach_id=?",[req.params.id]);
    res.json(training);
});

app.post("/api/coach/training/add", authMiddleware("coach"), async(req,res)=>{
    const {coach_id,date,activity} = req.body;
    await db.query("INSERT INTO training (coach_id,date,activity) VALUES (?,?,?)",[coach_id,date,activity]);
    res.json({message:"Training added"});
});

app.post("/api/coach/training/remove", authMiddleware("coach"), async(req,res)=>{
    const {id} = req.body;
    await db.query("DELETE FROM training WHERE id=?",[id]);
    res.json({message:"Training removed"});
});

app.get("/api/coach/matches/:id", authMiddleware("coach"), async(req,res)=>{
    const [matches] = await db.query("SELECT * FROM matches WHERE coach_id=?",[req.params.id]);
    res.json(matches);
});

app.post("/api/coach/match/add", authMiddleware("coach"), async(req,res)=>{
    const {coach_id,tournament,team_a,team_b,date,score_a,score_b,status} = req.body;
    await db.query("INSERT INTO matches (coach_id,tournament,team_a,team_b,date,score_a,score_b,status) VALUES (?,?,?,?,?,?,?,?)",
        [coach_id,tournament,team_a,team_b,date,score_a,score_b,status]);
    res.json({message:"Match added"});
});

app.post("/api/coach/match/remove", authMiddleware("coach"), async(req,res)=>{
    const {id} = req.body;
    await db.query("DELETE FROM matches WHERE id=?",[id]);
    res.json({message:"Match removed"});
});

app.get("/api/coach/analytics/:id", authMiddleware("coach"), async(req,res)=>{
    const coachId = req.params.id;
    const [matches] = await db.query("SELECT * FROM matches WHERE coach_id=?",[coachId]);
    const totalMatches = matches.length;
    const totalWins = matches.filter(m=>m.status==="completed" && m.score_a>m.score_b).length;
    const [teams] = await db.query("SELECT * FROM teams WHERE coach_id=?",[coachId]);
    const totalPlayers = teams.reduce((sum,t)=> sum + (t.members || 0),0);
    const playerStats = [];
    for(const t of teams){
        const [players] = await db.query("SELECT id,name FROM users WHERE team_id=?",[t.id]);
        for(const p of players){
            playerStats.push({name:p.name,matches:5,wins:2,points:10});
        }
    }
    res.json({matches:totalMatches,wins:totalWins,players:totalPlayers,playerStats});
});

app.get("/api/coach/profile/:id", authMiddleware("coach"), async(req,res)=>{
    const {id} = req.params;
    const [rows] = await db.query("SELECT id,name,email,phone,city,age FROM users WHERE id=? AND role='coach'",[id]);
    res.json(rows[0]||{});
});

app.put("/api/coach/update/:id", authMiddleware("coach"), async(req,res)=>{
    const {id} = req.params;
    const {name,email,phone,city,age} = req.body;
    await db.query("UPDATE users SET name=?,email=?,phone=?,city=?,age=? WHERE id=? AND role='coach'",[name,email,phone,city,age,id]);
    res.json({message:"Profile updated"});
});

app.put("/api/coach/password/:id", authMiddleware("coach"), async(req,res)=>{
    const {id} = req.params;
    const {password} = req.body;
    const hashed = await bcrypt.hash(password,8);
    await db.query("UPDATE users SET password=? WHERE id=? AND role='coach'",[hashed,id]);
    res.json({message:"Password updated"});
});

// ================= ADMIN APIs =================
app.get("/api/admin/dashboard", authMiddleware("admin"), async(req,res)=>{
    const [[totalUsers]] = await db.query("SELECT COUNT(*) AS total FROM users");
    const [[totalTournaments]] = await db.query("SELECT COUNT(*) AS total FROM tournaments");
    const [[totalMatches]] = await db.query("SELECT COUNT(*) AS total FROM matches");
    const [[totalBookings]] = await db.query("SELECT COUNT(*) AS total FROM bookings");
    const [[totalPayments]] = await db.query("SELECT COUNT(*) AS total FROM payments");
    res.json({totalUsers:totalUsers.total,totalTournaments:totalTournaments.total,totalMatches:totalMatches.total,totalBookings:totalBookings.total,totalPayments:totalPayments.total});
});

app.get("/api/admin/users", authMiddleware("admin"), async(req,res)=>{
    const [rows] = await db.query("SELECT id,name,email,role,created_at FROM users");
    res.json(rows);
});

app.delete("/api/admin/users/:id", authMiddleware("admin"), async(req,res)=>{
    const {id} = req.params;
    await db.query("DELETE FROM users WHERE id=?",[id]);
    res.json({message:"User deleted"});
});

app.get("/api/admin/tournaments", authMiddleware("admin"), async(req,res)=>{
    const [rows] = await db.query("SELECT * FROM tournaments");
    res.json(rows);
});

// Create a new tournament
app.post("/api/admin/tournaments", authMiddleware("admin"), async(req,res)=>{
    try{
        const {name, sport, start_date, end_date, entry_fee} = req.body;
        if(!name || !sport || !start_date || !end_date)
            return res.status(400).json({message:"All fields required"});
        await db.query(
            "INSERT INTO tournaments (name,sport,start_date,end_date,entry_fee) VALUES (?,?,?,?,?)",
            [name,sport,start_date,end_date,entry_fee]
        );
        res.status(201).json({message:"Tournament created"});
    } catch(err){
        console.log(err);
        res.status(500).json({message:"Server error"});
    }
});

// Delete a tournament
app.delete("/api/admin/tournaments/:id", authMiddleware("admin"), async(req,res)=>{
    try{
        const {id} = req.params;
        await db.query("DELETE FROM tournaments WHERE id=?",[id]);
        res.json({message:"Tournament deleted"});
    } catch(err){
        console.log(err);
        res.status(500).json({message:"Server error"});
    }
});

// Create a new match
app.post("/api/admin/matches", authMiddleware("admin"), async(req,res)=>{
    try{
        const { tournamentId, teamA, teamB, date } = req.body;
        if(!tournamentId || !teamA || !teamB || !date)
            return res.status(400).json({message:"All fields required"});

        await db.query(
            "INSERT INTO matches (tournament_id, team_a, team_b, match_date) VALUES (?,?,?,?)",
            [tournamentId, teamA, teamB, date]
        );

        res.status(201).json({message:"Match created successfully"});
    } catch(err){
        console.log(err);
        res.status(500).json({message:"Server error"});
    }
});


app.get("/api/admin/matches", authMiddleware("admin"), async(req,res)=>{
    const [rows] = await db.query("SELECT * FROM matches");
    res.json(rows);
});

app.get("/api/admin/bookings", authMiddleware("admin"), async(req,res)=>{
    const [rows] = await db.query("SELECT * FROM bookings");
    res.json(rows);
});

app.get("/api/admin/payments", authMiddleware("admin"), async(req,res)=>{
    const [rows] = await db.query("SELECT * FROM payments");
    res.json(rows);
});

// ================= SERVER =================
const PORT = 4000;
app.listen(PORT,()=>console.log(`🚀 Backend running at http://localhost:${PORT}`));
