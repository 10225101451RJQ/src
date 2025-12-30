#ifndef THREADS_FIXED_POINT_H
#define THREADS_FIXED_POINT_H

/* 17.14 fixed-point format */
#define F (1 << 14)

/* 整数 n 转定点数 */
#define INT_TO_FP(n) ((n) * F)

/* 定点数 x 转整数 (向零取整) */
#define FP_TO_INT(x) ((x) / F)

/* 定点数 x 转整数 (四舍五入) */
#define FP_TO_INT_ROUND(x) ((x) >= 0 ? ((x) + F / 2) / F : ((x) - F / 2) / F)

/* 定点数加减 */
#define ADD_FP(x, y) ((x) + (y))
#define SUB_FP(x, y) ((x) - (y))

/* 定点数与整数加减 */
#define ADD_FP_INT(x, n) ((x) + (n) * F)
#define SUB_FP_INT(x, n) ((x) - (n) * F)

/* 定点数乘除 (核心难点) */
#define MULT_FP(x, y) ((int64_t)(x) * (y) / F)
#define DIV_FP(x, y) ((int64_t)(x) * F / (y))

/* 定点数与整数乘除 */
#define MULT_FP_INT(x, n) ((x) * (n))
#define DIV_FP_INT(x, n) ((x) / (n))

#endif /* threads/fixed_point.h */
