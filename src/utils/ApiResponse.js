// Define a class named ApiResponse
class ApiResponse {
    // Constructor function that initializes instances of ApiResponse
    constructor(statusCode, data, message = "Success") {
        // Assign the provided statusCode to the instance property 'statusCode'
        this.statusCode = statusCode;
        // Assign the provided data to the instance property 'data'
        this.data = data;
        // Assign the provided message to the instance property 'message', defaulting to "Success" if not provided
        this.message = message;
        // Determine the success status based on the statusCode: 
        // If statusCode is less than 400, set success to true, otherwise false
        this.success = statusCode < 400;
    }
}

// Export the ApiResponse class to make it available for use in other modules
export { ApiResponse };
