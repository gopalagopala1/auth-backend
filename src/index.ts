import express, { Express, Request, Response, NextFunction } from "express";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import cors from "cors";
import jwt, { JwtPayload } from "jsonwebtoken";

dotenv.config();

const app: Express = express();
const port = process.env.PORT || 3001;

app.use(cors());
app.use(express.json());

interface User {
  id: string;
  username: string;
  password: string;
}

const users: User[] = [];

app.post(
  "/register",
  async (req: Request, res: Response, next: NextFunction) => {
    const { username, password } = req.body;

    const userExists = users.find((user) => user.username === username);

    if (userExists) {
      res.status(400).json({ message: "User already exists" });
      return;
    }

    try {
      const hashedPassword = await bcrypt.hash(password, 10);
      const newUser = {
        id: new Date().toISOString(),
        username,
        password: hashedPassword,
      };
      users.push(newUser);
      res.status(201).json({ message: "User created successfully" });
    } catch (error) {
      res.status(500).json({ message: "Internal server error" });
      next(error);
    }
  }
);

app.post("/login", async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  const { username, password } = req.body;

  // user will provide username and password and we will send back a token
  // that token will be used to authenticate the user for further

  if (!username || !password) {
    res.status(400).json({ message: "Username and password are required" });
    return;
  }

  const user = users.find((user) => user.username === username);

  if (!user) {
    res.status(400).json({ message: "User not found" });
    return;
  }

  try {
    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      res.status(400).json({ message: "Invalid password" });
      return;
    }

    const token = jwt.sign(
      { id: user.id, username: user.username },
      process.env.JWT_SECRET as string,
      { expiresIn: "5m" }
    );
    res.status(200).json({ token });
    return;
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Internal server error" });
    next(error);
  }
});

const verifyToken = (req: Request, res: Response, next: NextFunction) => {
  const token = req.headers.authorization?.split(" ")[1];
  console.log('token: ', token);
  if (!token) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }

  jwt.verify(token, process.env.JWT_SECRET as string, (err, decoded) => {
    if (err) {
      res.status(401).json({ message: "Unauthorized" });
      return;
    }

    req.body.user = decoded as JwtPayload;
    next();
  });
};

app.get(
  "/user/:username",
  verifyToken,
  (req: Request, res: Response, next: NextFunction) => {
    const username = req.params.username as string;
    const user = users.find((user) => user.username == username);

    if (!user) {
      res.status(404).json({ message: "User not found" });
      return;
    }

    const { password, ...userData } = user;
    res.status(200).json({ user: userData });
    return;
  }
);

app.get("/", (req: Request, res: Response) => {
  res.send("Hello World");
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
