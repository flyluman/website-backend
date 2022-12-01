import helmet from 'helmet';
import express from 'express';
import mongodb from 'mongodb';
import fetch from 'node-fetch';

const app = express();
const DB = process.env.DB || null;
const URI = process.env.DBURI || null;
const MongoClient = mongodb.MongoClient;

app.use(helmet());
app.use(express.json());
app.disable('x-powered-by');
app.use(express.urlencoded({ extended: true }));

const logger = async (req, res, next) => {

    res.header('Access-Control-Allow-Origin', '*');

    if (process.env.NODE_ENV === 'production') {
        if (req.headers['x-forwarded-proto'] !== 'https') return res.redirect(`https://flyluman.onrender.com${req.path}`);

        const ip = req.headers['x-forwarded-for'].split(',')[0];

        try {
            let data = await fetch(`http://ipwhois.app/json/${ip}?objects=ip,isp,city,country`);
            if (data.ok) {
                data = await data.json();
                req.address = data.ip;
                req.isp = data.isp;
                req.city = data.city;
                req.country = data.country;
            } else {
                req.address = req.isp = req.city = req.country = 'Failed to detect';
            }
        } catch (err) {
            console.log(err.stack);
        }

        let cluster, collection = 'log';
        if (req.country !== 'Bangladesh') collection = 'foreign-log';

        try {
            cluster = await MongoClient.connect(URI);
            const db = cluster.db(DB);

            await db.collection(collection).insertOne({
                ip: req.address,
                isp: req.isp,
                city: req.city,
                country: req.country,
                date: new Date(Date.now() + 21600000).toUTCString() + '+06',
                path: req.path,
                useragent: req.headers['user-agent']
            });

        } catch (err) {
            console.log(err.stack);
        }
        cluster.close();
    }
    next();
};


app.get('/whoami', logger, (req, res) => {
    res.json({
        ip: req.address,
        isp: req.isp,
        city: req.city,
        country: req.country
    });
});

app.post('/messenger', logger, async (req, res) => {

    let cluster;

    try {
        cluster = await MongoClient.connect(URI);
        const db = cluster.db(DB);

        await db.collection('msg').insertOne({
            ip: req.address,
            isp: req.isp,
            city: req.city,
            country: req.country,
            date: new Date(Date.now() + 21600000).toUTCString() + '+06',
            useragent: req.headers['user-agent'] || null,
            name: req.body.name || null,
            email: req.body.email || null,
            msg: req.body.msg || null,
        });

        res.redirect('https://flyluman.github.io');

    } catch (err) {
        console.log(err.stack);
    }
    cluster.close();
});

app.post('/query', async (req, res) => {
    if (req.body.name && req.body.pass && req.body.pass === process.env.QUERYPASS && req.body.name.match(/foreign-log|log|msg/g)) {

        let cluster;

        try {
            cluster = await MongoClient.connect(URI);
            const db = cluster.db(DB);

            let data = await db.collection(req.body.name).find().toArray();
            res.json(data.reverse());
        } catch (err) {
            console.log(err.stack);
            res.json({ 'query': 'failed' });
        }
        cluster.close();
    }
    else res.status(401).send('Unauthorized request to server.');
});

app.all('*', logger, (req, res) => res.status(404).send('Requested resource not found on server.'));

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`Listening at port ${PORT}`));