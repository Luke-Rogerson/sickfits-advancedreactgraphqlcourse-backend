const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const Mutations = {
  async createItem(parent, args, ctx, info) {
    const item = await ctx.db.mutation.createItem(
      {
        data: {
          ...args
        }
      },
      info
    );
    return item;
  },
  updateItem(parent, args, ctx, info) {
    // make a copy of the updates
    const updates = { ...args };
    // remove ID from the updates
    delete updates.id;
    // run the update method
    return ctx.db.mutation.updateItem(
      {
        data: updates,
        where: {
          id: args.id
        }
      },
      info
    );
  },
  async deleteItem(parent, args, ctx, info) {
    const where = { id: args.id };
    // 1. find the item
    const item = await ctx.db.query.item({ where }, `{ id title }`);
    // 2. check if they own it or have permissions
    // TODO
    // 3. Delete it
    return ctx.db.mutation.deleteItem({ where }, info);
  },
  async signUp(parent, args, ctx, info) {
    args.email = args.email.toLowerCase(); //always lowercase emails!
    // hash their password
    const password = await bcrypt.hash(args.password, 10);
    // create the user in the database
    const user = await ctx.db.mutation.createUser(
      {
        // ctx to access our db
        data: {
          ...args, // this will give us name: args.name, email: args.password, etc
          password,
          permissions: { set: ['USER'] } //permissions isn't just string field, but reaching out to external enum
        }
      },
      info
    ); //pass info as 2nd argument so it knows what data to return to client
    // create the JWT token for them. This means they don't have to sign in again when they've just signed up
    const token = jwt.sign({ userID: user.id }, process.env.APP_SECRET);
    // Set the JWT as a cookie on the response as they are now signed in
    ctx.response.cookie('token', token, {
      httpOnly: true, // prevent client Javascript from modifying cookie
      maxAge: 1000 * 60 * 60 * 24 * 365 // 1 year cookie
    });
    // Finally, return user to the browser
    return user;
  }
};

module.exports = Mutations;
