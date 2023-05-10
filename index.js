const fs = require('fs');
const path = require("path");
const FtpSrv = require('ftp-srv');
const mongoose = require('mongoose');
const express = require('express');
const bodyParser = require('body-parser');
require("colors");


console.log("[Предупреждение]: Для работы сервера нужно установить утилиты которые находятся в папке: ".red + "./Downloads/".yellow)
console.log("[Предупреждение]: Без базы данных вы не сможете войти как в сам FTP так и в его Браузерный-Интерфейс.".red)

mongoose.connect('mongodb://127.0.0.1:27017/ftp', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const db = mongoose.connection;

db.on("error", console.error.bind(console, "Ошибка подключения:".red));
db.once("open", function() {
  console.log(`${`[MongoDB]`.yellow}:`+` База данных подключена`.blue)
});

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
  role: {
    type: String,
    enum: ['admin', 'user'],
  },
});
const User = mongoose.model('User', userSchema);

const puppeteer = require("puppeteer");

(async () => {
  const browser = await puppeteer.launch({headless: false});
  const page = await browser.newPage();
  await page.goto("http://localhost:3000/");
  await browser.close()
})


const configSchema = new mongoose.Schema({
    host: {
      type: String,
      required: true,
    },
    port: {
      type: Number,
      required: true,
    },
});
const Config = mongoose.model("Config", configSchema);
const ftpCfg = Config.findOne();

const ftpServer = new FtpSrv({
  url: 'ftp://localhost:21', // URL для подключения к серверу
  greeting: 'Добро пожаловать на FTP-сервер', // приветственное сообщение для пользователей
  pasv_range: '3000-3100', // диапазон портов для пассивного режима
  anonymous: false, // запрещаем анонимный доступ
  file_format: 'ls', // формат вывода списка файлов
  file_sort: true, // сортировать файлы по имени
  anonymous: false, // запрещаем анонимный доступ
});



// functions
async function createAdmin() {
  const admin = await User.findOne({ role: 'admin' });
  if (!admin) {
    const password = "NetworkAdmin1401"
    const user = new User({ username: 'admin', password: password, role: 'admin' });
    await user.save();
    console.log('Создана учётная запись администратора: username=admin, password=NetworkAdmin1401');
  }
}
createAdmin();
//
const createUserHandler = async (req, res) => {
  try {
      const {
          username,
          password,
          role
      } = req.body;

      const existingUser = await User.findOne({username})
      if(existingUser) {
          return res.status(400).send(`Пользователь - ${username} уже существует`)
      }
      const newUser = new User({
          username,
          password,
          role,
      });
      await newUser.save();
      res.send(`Пользователь - ${username} создан`)
      res.end()
  } catch (error) {
      console.error(error);
    return  res.status(500).send("Серверная ошибка")
  }
};

const updateUserHandler = async (req, res) => {
  try {
      const {username, password, role} = req.body;
      const user = await User.findOne({username});

      if(!user) {
          return res.status(404).send("Пользователь не найден")
      }
      user.password = password;
      user.role = role;

      await user.save();
      res.send(`Данные об учётной записи пользователя - ${username} обновлены`);
      res.end()
    return  res.redirect("/panel/menu")
  } catch (error) {
      console.error(error);
     res.status(500).send("Серверная ошибка")
  }
};

const deleteUserHandler = async (req, res) => {
  try {
      const {username} = req.body;
      await User.deleteOne({username});
      res.redirect("/panel/menu")
      res.end()
  } catch (error) {
      console.error(error);
    return  res.status(500).send("Серверная ошибка")
  }
}

const updateFtpSettings = async (req, res) => {
  try {
    const { host, port } = req.body;

    const ftpSettings = await Config.findOne();

    if (ftpSettings) {
      ftpSettings.host = host;
      ftpSettings.port = port;
      await ftpSettings.save();
      res.send("FTP настройки обновлены");
    } else {
      const newFtpSettings = new Config({ host, port });
      await newFtpSettings.save();
      res.send("FTP настройки созданы");
    }
  } catch (error) {
    console.error(error);
    res.status(500).send("Ошибка сервера");
  }
};

// Обрабатываем событие "login" (аутентификация)
ftpServer.on('login', async ({ connection, username, password }, resolve, reject) => {
  const user = await User.findOne({ username });
  if (!user) {
    reject(new Error('Incorrect username or password'));
    console.error(`Ошибка авторизации пользователя ${username}: ${error.message}`);
  } else {
    const validPassword = (password === user.password);
    if (!validPassword) {
      reject(new Error('Incorrect username or password'));
      console.error(`Ошибка авторизации пользователя ${username}: ${error.message}`);
    } else if (user.role === 'admin') {
      const dir = __dirname + "/UserFolder/"
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir);
      }
      resolve({ root: __dirname + `/UserFolder/`});

      // Лог успешной авторизации администратора
      console.log(`[FTP]: Администратор '${username} авторизован в файловую систему. root: ${`/UserFolder/`}`);
    } else {
      const dir = __dirname + "/UserFolder/" + username
      if(!fs.existsSync(dir)) {
        fs.mkdirSync(dir)
      }
      resolve({ root: __dirname + '/UserFolder/' + username });
      // Лог успешной авторизации пользователя
      console.log(`[FTP]: Пользователь '${username}' авторизован в файловую систему. root: ${'/UserFolder/' + username} `);
    }
  }
});
ftpServer.on('client:connected', ({ connection }) => {
  console.log(`[FTP]: Клиент подключен: ${connection.ip}`);
});

ftpServer.on('client:disconnected', ({ connection }) => {
  console.log(`[FTP]: Клиент отключен: ${connection.ip}`);
});

// Обрабатываем событие "client-error" (ошибка клиента)
ftpServer.on('client-error', ({error, connection}) => {
  console.error(error);
  connection.reply(550, error.message);
});

// Обрабатываем загрузку файлов на сервер



// Обрабатываем событие "command:LIST" (запрос списка файлов)
ftpServer.on('command:LIST', ({connection, command}) => {
  // Получаем пользователя из соединения
  const user = connection.session.user;
  // Если это администратор, позволяем просмотр всех файлов
  if (user.role === 'admin') {
    return command.resolve();
  }
  // Если это пользователь, позволяем просмотр только своих файлов
  const path = command.arg;
  if (path !== user.username) {
    return command.reject(550, `Доступ к папке ${path}, - Запрещён`.red);
  }
  return command.resolve();
});




const webServer = express()

// Middleware для обработки данных из формы
webServer.use(bodyParser.urlencoded({ extended: false }));

const authenticateUser = async (req, res, next) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user) {
    return res.status(401).sendf('Доступ запрещён');
  }
  const validPassword = (password === user.password);
  if (!validPassword) {
    return res.status(401).send('Доступ запрещён');
  }
  if (user.role !== 'admin') {
    return res.status(403).send('Доступ запрещён');
  }
  req.user = user;
  next();
};


//post
webServer.post("/login", authenticateUser, (req, res) => {
  return res.redirect("/panel/menu")
});
webServer.post("/panel/user-settings/create", createUserHandler, (req, res) => {
  return res.redirect("/panel/user-settings/");
})
webServer.post("/panel/user-settings/:username/update", updateUserHandler, (req, res) => {
  return res.redirect("/panel/user-settings");
})
webServer.post("/panel/user-settings/:username/delete", deleteUserHandler, (req, res) => {
  return res.redirect("/panel/user-settings");
})

webServer.post("/panel/ftp-settings",updateFtpSettings, (req, res) => {
  res.redirect("/panel/menu");
});
//get
webServer.get('/panel/menu', (req, res) => {
  res.sendFile(__dirname + "/html/menu.html")
});
webServer.get("/panel/ftp-settings", (req, res) => {
  res.sendFile(__dirname + "/html/server-settings.html")
})

webServer.get("/panel/user-settings", (req, res) => {
  res.sendFile(__dirname + "/html/user-settings.html")
})

webServer.get("/", (req, res) => {
  res.sendFile(__dirname + "/html/login.html")
})


const chokidar = require('chokidar');
const { join } = require('path');

const watchedDir = './UserFolder/';
const logFileName = './logs/server.log';

// Создаем лог файл, если его нет
if (!fs.existsSync(logFileName)) {
  fs.writeFileSync(logFileName, '');
}

function writeToLog(message) {
  const time = new Date().toLocaleString('ru');
  const logMessage = `[${time}]: ${message}\n`;
  fs.appendFileSync(logFileName, logMessage);
  console.log(logMessage);
}
const watcher = chokidar.watch(watchedDir, { persistent: true });

watcher
  .on('add', (path) => {
    const message = `Добавлен файл: ${path}`;
    writeToLog(message);
  })
  .on('change', (path) => {
    const message = `Изменен файл: ${path}`;
    writeToLog(message);
  })
  .on('unlink', (path) => {
    const message = `Удален файл: ${path}`;
    writeToLog(message);
  })
  .on('addDir', (path) => {
    const message = `Добавлена папка: ${path}`;
    writeToLog(message);
  })
  .on('unlinkDir', (path) => {
    const message = `Удалена папка: ${path}`;
    writeToLog(message);
  })
  .on('error', (error) => {
    const message = `Произошла ошибка: ${error}`;
    writeToLog(message);
  })
  .on('ready', () => {
    const message = `Наблюдатель начал работу: ${watchedDir}`;
    writeToLog(message);
  });

webServer.listen(3000, () => {
  console.log("Сервер запущен на порту 3000, для подключения к интерфейсу используйте http://localhost:3000/".green)
})
ftpServer.listen()










