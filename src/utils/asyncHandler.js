// This code defines a utility function named asyncHandler, which is designed to handle asynchronous request handlers 
// in Express.js middleware. It provides two different approaches to handle asynchronous operations:

// 1. Promise-based approach:
//    - It takes a request handler function as input.
//    - It returns a new middleware function that handles asynchronous operations.
//    - Inside the middleware, it wraps the execution of the request handler in a Promise.
//    - If the Promise resolves successfully, the next middleware in the chain is called.
//    - If the Promise rejects with an error, the error is passed to the next middleware using the 'next' function.

// 2. Try and catch approach:
//    - It takes a request handler function as input.
//    - It returns a new middleware function that handles asynchronous operations.
//    - Inside the middleware, it awaits the execution of the request handler.
//    - If an error occurs during the execution, it catches the error using a try-catch block.
//    - It then sends an error response with the appropriate status code and error message.

// Both approaches essentially serve the same purpose of handling asynchronous operations in Express middleware, 
// but they employ different techniques to achieve it.



// This is the promise based approach 
const asyncHandler = (requestHandler) => {
    return (req,res,next)=> {
        Promise.resolve(requestHandler(req,res,next)).catch((err) => next(err))
    }
}

export { asyncHandler}

// This is the try nd catch approach for the same code

// const asyncHandler = (fn) => async(req,res,next) =>
// {
//     try {
//         await fn(req,res,next)
//     } catch (error) {
//         res.status(error.code || 500).json({
//             success: false,
//             message: error.message
//         })
//     }
// }