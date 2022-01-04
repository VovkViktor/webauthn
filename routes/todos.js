const express = require("express");
const { Todos } = require("../models/todos");
const verify = require("./authVerify");

const router = express.Router();

router.get("/", verify, async (req, res) => {
  try {
    const parseUrl = new URLSearchParams(req.query);
    const postId = parseUrl.get("id");

    if (postId) {
      const result = await Todos.findById(postId);
      return res.status(200).send(result);
    }

    const result = await Todos.find({ userId: req.user._id });

    res.status(200).json(result);
  } catch (error) {
    res.status(400).send(error);
  }
});

router.post("/", verify, async (req, res) => {
  try {
    const body = req.body;

    if (!body.title || !body.description) {
      return res
        .status(300)
        .send({ message: "title and description are requared fills" });
    }

    const result = await Todos.create({
      title: body.title,
      description: body.description,
      userId: req.user._id,
    });

    res.status(200).json(result);
  } catch (error) {
    res.status(400).send(error);
  }
});

router.delete("/", verify, async (req, res) => {
  try {
    const parseUrl = new URLSearchParams(req.query);
    const postId = parseUrl.get("id");

    await Todos.findByIdAndDelete(postId);

    res.status(200).json({ message: "delete was success" });
  } catch (error) {
    res.status(400).send(error);
  }
});

router.put("/", verify, async (req, res) => {
  try {
    const parseUrl = new URLSearchParams(req.query);
    const postId = parseUrl.get("id");

    if (!postId) {
      return res.status(300).send({ message: "query id is requared" });
    }

    const body = req.body;

    const result = await Todos.findByIdAndUpdate(
      postId,
      {
        ...body,
      },
      { returnDocument: "after", lean: true, runValidators: true }
    );

    res.status(200).json(result);
  } catch (error) {
    res.status(400).send(error);
  }
});

module.exports = router;
