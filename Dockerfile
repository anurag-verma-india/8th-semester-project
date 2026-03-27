# Node Base Image
FROM node:18-alpine


#Working Directry
WORKDIR /node

#Install the dependecies
# Only copy package.json & package-lock.json, so that docker caches this step if the dependencies didn't change
COPY package*.json ./
RUN npm install

#Copy the Code
COPY . .

RUN npm run test

EXPOSE 8000

#Run the code
CMD ["node","app.js"]
