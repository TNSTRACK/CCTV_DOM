// examples/authentication/jwt-middleware.ts
// Patrón estándar para autenticación y autorización

import jwt from 'jsonwebtoken';
import { Request, Response, NextFunction } from 'express';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

export interface AuthenticatedRequest extends Request {
  user?: {
    id: string;
    email: string;
    role: 'OPERATOR' | 'ADMINISTRATOR' | 'CLIENT_USER' | 'SUPERVISOR';
    companyId?: string;
  };
}

// PATRÓN: Middleware de autenticación con validación de usuario activo
export const authenticateToken = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    res.status(401).json({ error: 'Access token required' });
    return;
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET!) as any;
    
    // PATRÓN: Validación de usuario activo en cada request
    const user = await prisma.user.findUnique({
      where: { id: decoded.userId },
      select: {
        id: true,
        email: true,
        role: true,
        companyId: true,
        active: true,
      },
    });

    if (!user || !user.active) {
      res.status(401).json({ error: 'Invalid or inactive user' });
      return;
    }

    req.user = user;
    next();
  } catch (error) {
    res.status(403).json({ error: 'Invalid token' });
  }
};

// PATRÓN: Middleware de autorización por roles
export const requireRole = (allowedRoles: string[]) => {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    if (!req.user || !allowedRoles.includes(req.user.role)) {
      res.status(403).json({ error: 'Insufficient permissions' });
      return;
    }
    next();
  };
};

// PATRÓN: Middleware para filtrar por empresa (usuarios cliente)
export const enforceCompanyAccess = (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): void => {
  if (req.user?.role === 'CLIENT_USER' && req.user.companyId) {
    // Agregar filtro automático por empresa para usuarios cliente
    req.query.companyId = req.user.companyId;
  }
  next();
};