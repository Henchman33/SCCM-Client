#Requires -Version 5.0

Add-Type -AssemblyName PresentationFramework, PresentationCore
Add-Type -AssemblyName System.Windows.Forms

# Modern color scheme
$Colors = @{
    Primary = "#2E88E5"
    Secondary = "#1E53A0"
    Success = "#43A047"
    Danger = "#E53935"
    Warning = "#FB8C00"
    Light = "#F5F5F5"
    Dark = "#212121"
    Border = "#E0E0E0"
    Text = "#424242"
}

# XAML for Modern UI
$inputXML = @"
<Window x:Class="RemoteSoftwareCenter.MainWindow"
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Title="Remote Software Center" 
    Height="700" 
    Width="1000"
    Background="{StaticResource {x:Static SystemColors.WindowBrushKey}}"
    WindowStartupLocation="CenterScreen"
    ResizeMode="CanResize">
    
    <Window.Resources>
        <SolidColorBrush x:Key="PrimaryBrush" Color="#2E88E5"/>
        <SolidColorBrush x:Key="SecondaryBrush" Color="#1E53A0"/>
        <SolidColorBrush x:Key="SuccessBrush" Color="#43A047"/>
        <SolidColorBrush x:Key="DangerBrush" Color="#E53935"/>
        <SolidColorBrush x:Key="LightBrush" Color="#F5F5F5"/>
        <SolidColorBrush x:Key="BorderBrush" Color="#E0E0E0"/>
        <SolidColorBrush x:Key="TextBrush" Color="#424242"/>
        
        <Style TargetType="Button" x:Key="ModernButton">
            <Setter Property="Background" Value="{StaticResource PrimaryBrush}"/>
            <Setter Property="Foreground" Value="White"/>
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="FontWeight" Value="Medium"/>
            <Setter Property="Padding" Value="12,8"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border Background="{TemplateBinding Background}" 
                                CornerRadius="3"
                                Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter Property="Background" Value="{StaticResource SecondaryBrush}"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
        
        <Style TargetType="TextBox" x:Key="ModernTextBox">
            <Setter Property="Background" Value="White"/>
            <Setter Property="Foreground" Value="{StaticResource TextBrush}"/>
            <Setter Property="BorderBrush" Value="{StaticResource BorderBrush}"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Padding" Value="8,6"/>
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="Height" Value="36"/>
        </Style>
        
        <Style TargetType="PasswordBox" x:Key="ModernPasswordBox">
            <Setter Property="Background" Value="White"/>
            <Setter Property="Foreground" Value="{StaticResource TextBrush}"/>
            <Setter Property="BorderBrush" Value="{StaticResource BorderBrush}"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Padding" Value="8,6"/>
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="Height" Value="36"/>
        </Style>
        
        <Style TargetType="Label" x:Key="ModernLabel">
            <Setter Property="Foreground" Value="{StaticResource TextBrush}"/>
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="Margin" Value="0,0,0,6"/>
        </Style>
    </Window.Resources>
    
    <Grid Background="{StaticResource LightBrush}">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
        </Grid.RowDefinitions>
        
        <!-- Header -->
        <Grid Grid.Row="0" Background="{StaticResource PrimaryBrush}" Margin="0">
            <StackPanel Orientation="Vertical" Margin="24,20">
                <TextBlock Text="Remote Software Center" 
                           FontSize="28" 
                           FontWeight="Bold" 
                           Foreground="White"
                           Margin="0,0,0,8"/>
                <TextBlock Text="Manage applications, updates, and device compliance" 
                           FontSize="13" 
                           Foreground="#E3F2FD"
                           Opacity="0.9"/>
            </StackPanel>
        </Grid>
        
        <!-- Connection Section -->
        <Border Grid.Row="1" Background="White" BorderBrush="{StaticResource BorderBrush}" BorderThickness="0,0,0,1">
            <Grid Margin="24,16">
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="250"/>
                    <ColumnDefinition Width="250"/>
                    <ColumnDefinition Width="250"/>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>
                
                <StackPanel Grid.Column="0" Margin="0,0,12,0">
                    <Label Content="Computer Name" Style="{StaticResource ModernLabel}"/>
                    <TextBox x:Name="Input_ConnectTo" Style="{StaticResource ModernTextBox}" 
                             VerticalContentAlignment="Center"/>
                </StackPanel>
                
                <StackPanel Grid.Column="1" Margin="0,0,12,0">
                    <Label Content="Username" Style="{StaticResource ModernLabel}"/>
                    <TextBox x:Name="Input_Username" Style="{StaticResource ModernTextBox}" 
                             VerticalContentAlignment="Center"/>
                </StackPanel>
                
                <StackPanel Grid.Column="2" Margin="0,0,12,0">
                    <Label Content="Password" Style="{StaticResource ModernLabel}"/>
                    <PasswordBox x:Name="Input_Password" Style="{StaticResource ModernPasswordBox}" 
                                 VerticalContentAlignment="Center"/>
                </StackPanel>
                
                <CheckBox x:Name="Checkbox_UseAlternateCredentials" 
                         Grid.Column="3"
                         Content="Use Alternate Credentials"
                         VerticalAlignment="Bottom"
                         Margin="12,0,0,9"
                         Foreground="{StaticResource TextBrush}"
                         FontSize="12"/>
                
                <Button x:Name="Button_Connect" 
                       Content="Connect" 
                       Grid.Column="4"
                       Style="{StaticResource ModernButton}"
                       Width="100"
                       Height="36"
                       VerticalAlignment="Bottom"/>
            </Grid>
        </Border>
        
        <!-- Main Content Area -->
        <Grid Grid.Row="2">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="180"/>
                <ColumnDefinition Width="*"/>
            </Grid.ColumnDefinitions>
            
            <!-- Navigation Sidebar -->
            <StackPanel Grid.Column="0" Background="{StaticResource LightBrush}" 
                       Margin="0" Orientation="Vertical">
                <Button x:Name="Button_Applications" 
                       Content="📦 Applications" 
                       Style="{StaticResource ModernButton}"
                       Margin="12,12,12,6"
                       Background="Transparent"
                       Foreground="{StaticResource TextBrush}"
                       HorizontalAlignment="Stretch"
                       HorizontalContentAlignment="Left"/>
                
                <Button x:Name="Button_Updates" 
                       Content="🔄 Updates" 
                       Style="{StaticResource ModernButton}"
                       Margin="12,6,12,6"
                       Background="Transparent"
                       Foreground="{StaticResource TextBrush}"
                       HorizontalAlignment="Stretch"
                       HorizontalContentAlignment="Left"/>
                
                <Button x:Name="Button_OperatingSystems" 
                       Content="💻 Task Sequences" 
                       Style="{StaticResource ModernButton}"
                       Margin="12,6,12,6"
                       Background="Transparent"
                       Foreground="{StaticResource TextBrush}"
                       HorizontalAlignment="Stretch"
                       HorizontalContentAlignment="Left"/>
                
                <Button x:Name="Button_InstallationStatus" 
                       Content="✓ Installation Status" 
                       Style="{StaticResource ModernButton}"
                       Margin="12,6,12,6"
                       Background="Transparent"
                       Foreground="{StaticResource TextBrush}"
                       HorizontalAlignment="Stretch"
                       HorizontalContentAlignment="Left"/>
                
                <Button x:Name="Button_DeviceCompliance" 
                       Content="🛡️ Device Compliance" 
                       Style="{StaticResource ModernButton}"
                       Margin="12,6,12,6"
                       Background="Transparent"
                       Foreground="{StaticResource TextBrush}"
                       HorizontalAlignment="Stretch"
                       HorizontalContentAlignment="Left"/>
                
                <Button x:Name="Button_Options" 
                       Content="⚙️ Options" 
                       Style="{StaticResource ModernButton}"
                       Margin="12,6,12,6"
                       Background="Transparent"
                       Foreground="{StaticResource TextBrush}"
                       HorizontalAlignment="Stretch"
                       HorizontalContentAlignment="Left"/>
                
                <Button x:Name="Button_ClientActions" 
                       Content="🔧 Client Actions" 
                       Style="{StaticResource ModernButton}"
                       Margin="12,6,12,6"
                       Background="Transparent"
                       Foreground="{StaticResource TextBrush}"
                       HorizontalAlignment="Stretch"
                       HorizontalContentAlignment="Left"/>
            </StackPanel>
            
            <!-- Content Area -->
            <Border Grid.Column="1" Background="White" BorderBrush="{StaticResource BorderBrush}" BorderThickness="1,0,0,0">
                <Grid Margin="24">
                    <Grid.RowDefinitions>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="*"/>
                        <RowDefinition Height="Auto"/>
                    </Grid.RowDefinitions>
                    
                    <!-- Content Header -->
                    <TextBlock x:Name="ContentHeader" 
                              Grid.Row="0"
                              Text="Welcome" 
                              FontSize="24" 
                              FontWeight="Bold" 
                              Foreground="{StaticResource TextBrush}"
                              Margin="0,0,0,16"/>
                    
                    <!-- ListView for Applications -->
                    <ListView x:Name="ApplicationsListView" 
                             Grid.Row="1" 
                             Visibility="Hidden"
                             BorderThickness="1"
                             BorderBrush="{StaticResource BorderBrush}">
                        <ListView.View>
                            <GridView>
                                <GridViewColumn Header="Name" Width="300"/>
                                <GridViewColumn Header="Version" Width="100"/>
                                <GridViewColumn Header="Status" Width="150"/>
                                <GridViewColumn Header="Error Code" Width="100"/>
                            </GridView>
                        </ListView.View>
                    </ListView>
                    
                    <!-- Status/Progress Area -->
                    <StackPanel Grid.Row="2" Orientation="Horizontal" Margin="0,16,0,0">
                        <ProgressBar x:Name="ProgressBar" 
                                    Width="200" 
                                    Height="4" 
                                    Visibility="Hidden"
                                    Foreground="{StaticResource PrimaryBrush}"/>
                        <TextBlock x:Name="StatusText" 
                                  Text="" 
                                  Margin="12,0,0,0" 
                                  VerticalAlignment="Center"
                                  FontSize="12"
                                  Foreground="{StaticResource TextBrush}"/>
                    </StackPanel>
                </Grid>
            </Border>
        </Grid>
    </Grid>
</Window>
"@

# Remove WPF parsing issues
$inputXML = $inputXML -replace 'mc:Ignorable="d"', '' -replace "x:N", 'N' -replace '^<Win.*', '<Window'

[void][System.Reflection.Assembly]::LoadWithPartialName('presentationframework')
[xml]$XAML = $inputXML

$reader = (New-Object System.Xml.XmlNodeReader $xaml)
try {
    $Form = [Windows.Markup.XamlReader]::Load($reader)
} catch {
    Write-Error "Unable to load XAML: $_"
    exit
}

# Store Form Objects
$xaml.SelectNodes("//*[@Name]") | ForEach-Object { 
    Set-Variable -Name "WPF$($_.Name)" -Value $Form.FindName($_.Name) -Scope Global
}

# Credentials storage
$Script:Credentials = $null

# Button Event: Connect
$WPFButton_Connect.Add_Click({
    $RemoteComputer = $WPFInput_ConnectTo.Text
    
    if ([string]::IsNullOrWhiteSpace($RemoteComputer)) {
        [System.Windows.MessageBox]::Show("Please enter a computer name", "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
        return
    }
    
    # Prepare credentials if alternate credentials are checked
    if ($WPFCheckbox_UseAlternateCredentials.IsChecked) {
        $Username = $WPFInput_Username.Text
        $Password = $WPFInput_Password.Password
        
        if ([string]::IsNullOrWhiteSpace($Username) -or [string]::IsNullOrWhiteSpace($Password)) {
            [System.Windows.MessageBox]::Show("Please enter username and password", "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
            return
        }
        
        $SecurePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force
        $Script:Credentials = New-Object System.Management.Automation.PSCredential($Username, $SecurePassword)
    } else {
        $Script:Credentials = $null
    }
    
    try {
        $TestConnection = Test-Connection -ComputerName $RemoteComputer -Count 1 -ErrorAction Stop
        
        # Get WMI data with credentials if provided
        $WMIParams = @{
            ComputerName = $RemoteComputer
            Namespace = "root\ccm\dcm"
            Query = "SELECT * FROM SMS_DesiredConfiguration"
            ErrorAction = "Stop"
        }
        
        if ($Script:Credentials) {
            $WMIParams['Credential'] = $Script:Credentials
        }
        
        Get-WmiObject @WMIParams | Out-Null
        
        $WPFButton_Connect.Content = "Connected ✓"
        $WPFButton_Connect.Background = $Colors.Success
        $WPFInput_ConnectTo.IsEnabled = $false
        
        $WPFContentHeader.Text = "Connected to: $RemoteComputer"
        $WPFStatusText.Text = "Ready"
        
    } catch {
        [System.Windows.MessageBox]::Show("Failed to connect: $_", "Connection Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
        $WPFButton_Connect.Content = "Retry"
        $WPFButton_Connect.Background = [System.Windows.Media.Brush]::Parse($Colors.Danger)
    }
})

# Button Event: Applications
$WPFButton_Applications.Add_Click({
    $WPFContentHeader.Text = "📦 Applications"
    $WPFApplicationsListView.Visibility = "Visible"
    $WPFStatusText.Text = "Loading applications..."
    
    $RemoteComputer = $WPFInput_ConnectTo.Text
    $WPFProgressBar.Visibility = "Visible"
    
    # Simulate loading
    $WPFProgressBar.IsIndeterminate = $true
    
    Start-Sleep -Milliseconds 500
    $WPFProgressBar.IsIndeterminate = $false
    $WPFStatusText.Text = "Applications loaded"
})

# Button Event: Updates
$WPFButton_Updates.Add_Click({
    $WPFContentHeader.Text = "🔄 Updates"
    $WPFApplicationsListView.Visibility = "Hidden"
    $WPFStatusText.Text = "Fetching available updates..."
})

# Button Event: Task Sequences
$WPFButton_OperatingSystems.Add_Click({
    $WPFContentHeader.Text = "💻 Task Sequences"
    $WPFApplicationsListView.Visibility = "Hidden"
    $WPFStatusText.Text = "Loading task sequences..."
})

# Button Event: Installation Status
$WPFButton_InstallationStatus.Add_Click({
    $WPFContentHeader.Text = "✓ Installation Status"
    $WPFApplicationsListView.Visibility = "Hidden"
    $WPFStatusText.Text = "Loading installation status..."
})

# Button Event: Device Compliance
$WPFButton_DeviceCompliance.Add_Click({
    $WPFContentHeader.Text = "🛡️ Device Compliance"
    $WPFApplicationsListView.Visibility = "Hidden"
    $WPFStatusText.Text = "Checking device compliance..."
})

# Button Event: Options
$WPFButton_Options.Add_Click({
    $WPFContentHeader.Text = "⚙️ Options"
    $WPFApplicationsListView.Visibility = "Hidden"
    $WPFStatusText.Text = "Settings area"
})

# Button Event: Client Actions
$WPFButton_ClientActions.Add_Click({
    $WPFContentHeader.Text = "🔧 Client Actions"
    $WPFApplicationsListView.Visibility = "Hidden"
    $WPFStatusText.Text = "Available client actions"
})

# Show the Form
$Form.ShowDialog() | Out-Null
