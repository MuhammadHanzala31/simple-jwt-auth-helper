import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';

export const generateToken = (payload, secret, expiresIn = '7d') => {
    return jwt.sign(payload, secret, { expiresIn });
};

export const verifyToken = (token, secret) => {
    return jwt.verify(token, secret);
};

export const hashPassword = async (password) => {
    const salt = await bcrypt.genSalt(10);
    return await bcrypt.hash(password, salt);
};

export const comparePassword = async (password, hashedPassword) => {
    return await bcrypt.compare(password, hashedPassword);
};
