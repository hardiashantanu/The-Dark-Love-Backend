// Define a class named ApiError that extends the built-in Error class

// one of the reason for making this response utitlity is to avoid the fake 200 response

class ApiError extends Error {
    // Constructor function that initializes instances of ApiError
    constructor(statusCode, message = "Something went wrong", errors = [], stack = "") {
        // Call the constructor of the Error class with the provided message
        super(message);
        // Assign the provided statusCode to the instance property 'statusCode'
        this.statusCode = statusCode;
        // Initialize the 'data' property to null (since it's an error, there might not be data)
        this.data = null;
        // Assign the provided message to the instance property 'message'
        this.message = message;
        // Set the 'success' property to false, since this represents an error
        this.success = false;
        // Assign the provided errors array to the instance property 'errors'
        this.errors = errors;

        // If a stack trace is provided, assign it to the 'stack' property,
        // Otherwise, capture the stack trace using Error.captureStackTrace()
        if (stack) {
            this.stack = stack;
        } else {
            Error.captureStackTrace(this, this.constructor);
        }
    }
}

// Export the ApiError class to make it available for use in other modules
export { ApiError };
