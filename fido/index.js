import express from 'express';
import uafRouter from './uaf/router'

const router = express.Router();

router.use('/uaf/', uafRouter);


module.exports = router;