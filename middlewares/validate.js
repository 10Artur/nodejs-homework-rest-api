const { errorHttp } = require("../error");

const validate = (schema) => {
    const func = (req, res, next) => {
        const { error } = schema.validate(req.body);
        if (error) {
            next(errorHttp(400, "missing required name field"));
        }
        next();
    };
    return func;
};

module.exports = validate;