public void GetProductByName(string productName)
{
    using (var context = new YourDbContext())
    {
        var products = context.Products
                              .Where(p => p.Name == productName)
                              .ToList();
        foreach (var product in products)
        {
            Console.WriteLine($"Product: {product.Name}");
        }
    }
}
