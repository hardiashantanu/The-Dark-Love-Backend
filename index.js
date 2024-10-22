// require('dotenv').config({path: './env'})
import dotenv from "dotenv";
import connectDB from "./src/db/index.js";
import { app } from "./app.js";


dotenv.config({
  path: "./.env",
});

connectDB().then(() => {
  app.listen(process.env.PORT || 8000, () => {
    console.log(`\n⚙️ Server is running at port : ${process.env.PORT}`);
  });
});