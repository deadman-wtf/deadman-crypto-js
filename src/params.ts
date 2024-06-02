import { p256 } from "@noble/curves/p256";
import { Point } from "./types";

export const theCurve = p256;
export const theCurveN = theCurve.CURVE.n;
export const Hx = BigInt("0x698bea63dc44a344663ff1429aea10842df27b6b991ef25866b2c6c02cdcc5be");
export const Hy = BigInt("0x4992f5f57d7e55b0d637ed659b98857242597f00da1d893e681bf4c62627b249");
export const G1: Point = new Point(theCurve.CURVE.Gx, theCurve.CURVE.Gy);
export const G2: Point = new Point(Hx, Hy);
