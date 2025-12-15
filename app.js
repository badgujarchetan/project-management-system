import dotenv from "dotenv";
dotenv.config();
import express from "express";

const app = express();
import cors from "cors";
app.use(express.json({ limit: "16kb" }));
app.use(express.urlencoded({ extended: true, limit: "16kb" }));
app.use(
  cors({
    origin: process.env.CORS_ORIGIN || "*",
    methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    credentials: true,
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

app.use(express.static("public"));

import helthcheckRouter from "./routes/healthcheck_routes.js";

import authRouter from "./routes/auth_routes.js";
app.use("/api/v1/healthcheck", helthcheckRouter);
app.use("/api/v1/auth", authRouter);

app.get("/", (req, res) => {
  res.send("welcome to backend");
});

export default app;
