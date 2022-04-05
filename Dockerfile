FROM node:lts

#Crearte app directory
WORKDIR /usr/app

COPY .npmrc .
COPY package.json .
RUN npm install --quiet

COPY . .

EXPOSE 443
EXPOSE 80
CMD ["npm", "start"]
