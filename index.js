import dotenv from "dotenv";
dotenv.config();
import connectDB from "./db/mongoose_connection.js";
connectDB();
import app from "./app.js";

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`app listening on ${PORT}`);
});
