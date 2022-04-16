import Users from "../models/UserModel.js";
import jwt from "jsonwebtoken";

export const refreshToken = async (req, res) => {
  try {
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken)
      return res.status(401).json({ msg: "refresh_token tidak ada" });
    const user = await Users.findAll({
      where: {
        refresh_token: refreshToken,
      },
    });
    if (!user[0]) return res.status(403).json({ msg: "users tidak ada" });
    jwt.verify(
      refreshToken,
      process.env.REFRESH_TOKEN_SECRET,
      (err, decoded) => {
        if (err) return res.sendStatus(403);
        const userId = user[0].id;
        const email = user[0].email;
        const name = user[0].name;
        const accessToken = jwt.sign(
          { userId, name, email },
          process.env.ACCESS_TOKEN_SECRET,
          { expiresIn: "15s" }
        );
        res.json({ accessToken });
      }
    );
  } catch (error) {
    console.log(error);
  }
};
