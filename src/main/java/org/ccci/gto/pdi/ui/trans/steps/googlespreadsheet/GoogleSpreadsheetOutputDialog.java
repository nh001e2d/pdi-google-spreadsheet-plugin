package org.ccci.gto.pdi.ui.trans.steps.googlespreadsheet;

import com.google.gdata.client.spreadsheet.FeedURLFactory;
import com.google.gdata.client.spreadsheet.SpreadsheetService;
import com.google.gdata.data.spreadsheet.SpreadsheetEntry;
import com.google.gdata.data.spreadsheet.SpreadsheetFeed;
import com.google.gdata.data.spreadsheet.WorksheetEntry;
import com.google.gdata.data.spreadsheet.WorksheetFeed;

import org.ccci.gto.pdi.trans.steps.googlespreadsheet.GoogleSpreadsheet;
import org.ccci.gto.pdi.trans.steps.googlespreadsheet.GoogleSpreadsheetOutputMeta;
import org.eclipse.swt.SWT;
import org.eclipse.swt.custom.CTabFolder;
import org.eclipse.swt.custom.CTabItem;
import org.eclipse.swt.events.*;
import org.eclipse.swt.layout.FormAttachment;
import org.eclipse.swt.layout.FormData;
import org.eclipse.swt.layout.FormLayout;
import org.eclipse.swt.widgets.*;
import org.pentaho.di.core.Const;
import org.pentaho.di.core.Props;
import org.pentaho.di.i18n.BaseMessages;
import org.pentaho.di.trans.TransMeta;
import org.pentaho.di.trans.step.BaseStepMeta;
import org.pentaho.di.trans.step.StepDialogInterface;
import org.pentaho.di.ui.core.dialog.EnterSelectionDialog;
import org.pentaho.di.ui.core.dialog.ErrorDialog;
import org.pentaho.di.ui.core.widget.TextVar;
import org.pentaho.di.ui.trans.step.BaseStepDialog;

import javax.security.auth.x500.X500Principal;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;

@SuppressWarnings("WeakerAccess")
public class GoogleSpreadsheetOutputDialog extends BaseStepDialog implements StepDialogInterface {

    private static final Class<?> PKG = GoogleSpreadsheetOutputMeta.class;

    private final GoogleSpreadsheetOutputMeta meta;

    private Label privateKeyInfo;
    private Label testServiceAccountInfo;
    private TextVar serviceEmail;
    private TextVar pkcsFilename;
    private KeyStore privateKeyStore;
    private TextVar spreadsheetKey;
    private TextVar worksheetId;

    public GoogleSpreadsheetOutputDialog(Shell parent, Object in, TransMeta meta, String name) {
        super( parent, (BaseStepMeta) in, meta, name );
        this.meta = (GoogleSpreadsheetOutputMeta) in;
    }

    @Override
    public String open() {
        Shell parent = this.getParent();
        Display display = parent.getDisplay();

        shell = new Shell( parent, SWT.DIALOG_TRIM | SWT.RESIZE | SWT.MAX | SWT.MIN );
        props.setLook( shell );
        setShellImage( shell, meta );

        ModifyListener modifiedListener = new ModifyListener() {
            @Override
            public void modifyText( ModifyEvent e ) {
                meta.setChanged();
            }
        };
        changed = meta.hasChanged();

        FormLayout formLayout = new FormLayout();
        formLayout.marginWidth = Const.FORM_MARGIN;
        formLayout.marginHeight = Const.FORM_MARGIN;

        shell.setLayout( formLayout );
        shell.setText( "Google Spreadsheet Output" );

        int middle = props.getMiddlePct();
        int margin = Const.MARGIN;

        // stepname - Label
        wlStepname = new Label( shell, SWT.RIGHT );
        wlStepname.setText( BaseMessages.getString( PKG, "System.Label.StepName" ) );
        props.setLook( wlStepname );
        fdlStepname = new FormData();
        fdlStepname.top = new FormAttachment( 0, margin );
        fdlStepname.left = new FormAttachment( 0, 0 );
        fdlStepname.right = new FormAttachment( middle, -margin );
        wlStepname.setLayoutData( fdlStepname );

        // stepname - Text
        wStepname = new Text( shell, SWT.SINGLE | SWT.LEFT | SWT.BORDER );
        wStepname.setText( stepname );
        props.setLook( wStepname );
        wStepname.addModifyListener( modifiedListener );
        fdStepname = new FormData();
        fdStepname.top = new FormAttachment( 0, margin );
        fdStepname.left = new FormAttachment( middle, 0 );
        fdStepname.right = new FormAttachment( 100, 0 );
        wStepname.setLayoutData( fdStepname );

        CTabFolder tabFolder = new CTabFolder( shell, SWT.BORDER );
        props.setLook( tabFolder, Props.WIDGET_STYLE_TAB );
        tabFolder.setSimple( false );

        /*
         * BEGIN Service Account Tab
         */
        CTabItem serviceAccountTab = new CTabItem( tabFolder, SWT.NONE );
        serviceAccountTab.setText( "Service Account" );

        Composite serviceAccountComposite = new Composite( tabFolder, SWT.NONE );
        props.setLook( serviceAccountComposite );

        FormLayout serviceAccountLayout = new FormLayout();
        serviceAccountLayout.marginWidth = 3;
        serviceAccountLayout.marginHeight = 3;
        serviceAccountComposite.setLayout( serviceAccountLayout );

        // serviceEmail - Label
        Label serviceEmailLabel = new Label( serviceAccountComposite, SWT.RIGHT );
        serviceEmailLabel.setText( "Email address" );
        props.setLook( serviceEmailLabel );
        FormData serviceEmailLabelData = new FormData();
        serviceEmailLabelData.top = new FormAttachment( 0, margin );
        serviceEmailLabelData.left = new FormAttachment( 0, 0 );
        serviceEmailLabelData.right = new FormAttachment( middle, -margin );
        serviceEmailLabel.setLayoutData( serviceEmailLabelData );

        // serviceEmail - Text
        serviceEmail = new TextVar(transMeta, serviceAccountComposite, SWT.SINGLE | SWT.LEFT | SWT.BORDER );
        props.setLook( serviceEmail );
        serviceEmail.addModifyListener( modifiedListener );
        FormData serviceEmailData = new FormData();
        serviceEmailData.top = new FormAttachment( 0, margin );
        serviceEmailData.left = new FormAttachment( middle, 0 );
        serviceEmailData.right = new FormAttachment( 100, 0 );
        serviceEmail.setLayoutData( serviceEmailData );

        // privateKey - Label
        Label privateKeyLabel = new Label( serviceAccountComposite, SWT.RIGHT );
        privateKeyLabel.setText( "Private Key (p12 file)" );
        props.setLook( privateKeyLabel );
        FormData privateKeyLabelForm = new FormData();
        privateKeyLabelForm.top = new FormAttachment( serviceEmail, margin );
        privateKeyLabelForm.left = new FormAttachment( 0, 0 );
        privateKeyLabelForm.right = new FormAttachment( middle, -margin );
        privateKeyLabel.setLayoutData( privateKeyLabelForm );

        // privateKey - Button
        Button privateKeyButton = new Button( serviceAccountComposite, SWT.PUSH | SWT.CENTER );
        props.setLook( privateKeyButton );
        privateKeyButton.setText( "Browse" );
        FormData privateKeyButtonForm = new FormData();
        privateKeyButtonForm.top = new FormAttachment( serviceEmail, margin );
        privateKeyButtonForm.right = new FormAttachment( 100, 0 );
        privateKeyButton.setLayoutData( privateKeyButtonForm );
        
        pkcsFilename = new TextVar(transMeta, serviceAccountComposite, SWT.SINGLE | SWT.LEFT | SWT.BORDER);
        props.setLook(pkcsFilename);
        FormData fdPkcsFilename = new FormData();
        fdPkcsFilename.top = new FormAttachment(serviceEmail, margin);
        fdPkcsFilename.left = new FormAttachment(middle, 0);
        fdPkcsFilename.right = new FormAttachment(privateKeyButton, 0);
        pkcsFilename.setLayoutData(fdPkcsFilename);
        
        privateKeyInfo = new Label( serviceAccountComposite, SWT.LEFT );
        props.setLook( privateKeyInfo );
        FormData privateKeyInfoData = new FormData();
        privateKeyInfoData.top = new FormAttachment( pkcsFilename, margin );
        privateKeyInfoData.left = new FormAttachment( middle, 0 );
        privateKeyInfoData.right = new FormAttachment( 100, 0 );
        privateKeyInfo.setLayoutData( privateKeyInfoData );

        // test service - Button
        Button testServiceAccountButton = new Button( serviceAccountComposite, SWT.PUSH | SWT.CENTER );
        props.setLook( testServiceAccountButton );
        testServiceAccountButton.setText( "Test Connection" );
        FormData testServiceAccountButtonData = new FormData();
        testServiceAccountButtonData.bottom = new FormAttachment( 100, 0 );
        testServiceAccountButtonData.right = new FormAttachment( middle, -margin );
        testServiceAccountButton.setLayoutData( testServiceAccountButtonData );

        testServiceAccountInfo = new Label( serviceAccountComposite, SWT.LEFT );
        props.setLook( testServiceAccountInfo );
        FormData testServiceAccountInfoData = new FormData();
        testServiceAccountInfoData.bottom = new FormAttachment( 100, -margin * 2 );
        testServiceAccountInfoData.left = new FormAttachment( middle, 0 );
        testServiceAccountInfoData.right = new FormAttachment( 100, 0 );
        testServiceAccountInfo.setLayoutData( testServiceAccountInfoData );

        FormData serviceAccountCompositeData = new FormData();
        serviceAccountCompositeData.left = new FormAttachment( 0, 0 );
        serviceAccountCompositeData.top = new FormAttachment( 0, 0 );
        serviceAccountCompositeData.right = new FormAttachment( 100, 0 );
        serviceAccountCompositeData.bottom = new FormAttachment( 100, 0 );
        serviceAccountComposite.setLayoutData( serviceAccountCompositeData );

        serviceAccountComposite.layout();
        serviceAccountTab.setControl( serviceAccountComposite );
        /*
         * END Service Account Tab
         */

        /*
         * BEGIN Spreadsheet Tab
         */
        CTabItem spreadsheetTab = new CTabItem( tabFolder, SWT.NONE );
        spreadsheetTab.setText( "Spreadsheet" );

        Composite spreadsheetComposite = new Composite( tabFolder, SWT.NONE );
        props.setLook( spreadsheetComposite );

        FormLayout spreadsheetLayout = new FormLayout();
        spreadsheetLayout.marginWidth = 3;
        spreadsheetLayout.marginHeight = 3;
        spreadsheetComposite.setLayout( spreadsheetLayout );

        // spreadsheetKey - Label
        Label spreadsheetKeyLabel = new Label( spreadsheetComposite, SWT.RIGHT );
        spreadsheetKeyLabel.setText( "Spreadsheet Key" );
        props.setLook( spreadsheetKeyLabel );
        FormData spreadsheetKeyLabelData = new FormData();
        spreadsheetKeyLabelData.top = new FormAttachment( 0, margin );
        spreadsheetKeyLabelData.left = new FormAttachment( 0, 0 );
        spreadsheetKeyLabelData.right = new FormAttachment( middle, -margin );
        spreadsheetKeyLabel.setLayoutData( spreadsheetKeyLabelData );

        // spreadsheetKey - Button
        Button spreadsheetKeyButton = new Button( spreadsheetComposite, SWT.PUSH | SWT.CENTER );
        spreadsheetKeyButton.setText( "Browse" );
        props.setLook( spreadsheetKeyButton );
        FormData spreadsheetKeyButtonData = new FormData();
        spreadsheetKeyButtonData.top = new FormAttachment( 0, margin );
        spreadsheetKeyButtonData.right = new FormAttachment( 100, 0 );
        spreadsheetKeyButton.setLayoutData( spreadsheetKeyButtonData );

        // spreadsheetKey - Text
        spreadsheetKey = new TextVar(transMeta, spreadsheetComposite, SWT.SINGLE | SWT.LEFT | SWT.BORDER );
        props.setLook( spreadsheetKey );
        spreadsheetKey.addModifyListener( modifiedListener );
        FormData spreadsheetKeyData = new FormData();
        spreadsheetKeyData.top = new FormAttachment( 0, margin );
        spreadsheetKeyData.left = new FormAttachment( middle, 0 );
        spreadsheetKeyData.right = new FormAttachment( spreadsheetKeyButton, -margin );
        spreadsheetKey.setLayoutData( spreadsheetKeyData );

        // worksheetId - Label
        Label worksheetIdLabel = new Label( spreadsheetComposite, SWT.RIGHT );
        worksheetIdLabel.setText( "Worksheet Id" );
        props.setLook( worksheetIdLabel );
        FormData worksheetIdLabelData = new FormData();
        worksheetIdLabelData.top = new FormAttachment( spreadsheetKeyButton, margin );
        worksheetIdLabelData.left = new FormAttachment( 0, 0 );
        worksheetIdLabelData.right = new FormAttachment( middle, -margin );
        worksheetIdLabel.setLayoutData( worksheetIdLabelData );

        // worksheetId - Button
        Button worksheetIdButton = new Button( spreadsheetComposite, SWT.PUSH | SWT.CENTER );
        worksheetIdButton.setText( "Browse" );
        props.setLook( worksheetIdButton );
        FormData worksheetIdButtonData = new FormData();
        worksheetIdButtonData.top = new FormAttachment( spreadsheetKeyButton, margin );
        worksheetIdButtonData.right = new FormAttachment( 100, 0 );
        worksheetIdButton.setLayoutData( worksheetIdButtonData );

        // worksheetId - Text
        worksheetId = new TextVar(transMeta, spreadsheetComposite, SWT.SINGLE | SWT.LEFT | SWT.BORDER );
        props.setLook( worksheetId );
        worksheetId.addModifyListener( modifiedListener );
        FormData worksheetIdData = new FormData();
        worksheetIdData.top = new FormAttachment( spreadsheetKeyButton, margin );
        worksheetIdData.left = new FormAttachment( middle, 0 );
        worksheetIdData.right = new FormAttachment( worksheetIdButton, -margin );
        worksheetId.setLayoutData( worksheetIdData );

        FormData spreadsheetCompositeData = new FormData();
        spreadsheetCompositeData.left = new FormAttachment( 0, 0 );
        spreadsheetCompositeData.top = new FormAttachment( 0, 0 );
        spreadsheetCompositeData.right = new FormAttachment( 100, 0 );
        spreadsheetCompositeData.bottom = new FormAttachment( 100, 0 );
        spreadsheetComposite.setLayoutData( spreadsheetCompositeData );

        spreadsheetComposite.layout();
        spreadsheetTab.setControl( spreadsheetComposite );
        /*
         * END Spreadsheet Tab
         */

        /*
         * BEGIN Fields Tab
         */
        /*
        CTabItem fieldsTab = new CTabItem( tabFolder, SWT.NONE );
        fieldsTab.setText( "Fields" );

        Composite fieldsComposite = new Composite( tabFolder, SWT.NONE );
        props.setLook( fieldsComposite );

        FormLayout fieldsLayout = new FormLayout();
        fieldsLayout.marginWidth = 3;
        fieldsLayout.marginHeight = 3;
        fieldsComposite.setLayout( fieldsLayout );

        FormData fieldsCompositeData = new FormData();
        fieldsCompositeData.left = new FormAttachment( 0, 0 );
        fieldsCompositeData.top = new FormAttachment( 0, 0 );
        fieldsCompositeData.right = new FormAttachment( 100, 0 );
        fieldsCompositeData.bottom = new FormAttachment( 100, 0 );
        fieldsComposite.setLayoutData( fieldsCompositeData );

        fieldsComposite.layout();
        fieldsTab.setControl( fieldsComposite );
        */
        /*
         * END Fields Tab
         */

        FormData tabFolderData = new FormData();
        tabFolderData.left = new FormAttachment( 0, 0 );
        tabFolderData.top = new FormAttachment( wStepname, margin );
        tabFolderData.right = new FormAttachment( 100, 0 );
        tabFolderData.bottom = new FormAttachment( 100, -50 );
        tabFolder.setLayoutData( tabFolderData );

        // OK and cancel buttons
        wOK = new Button( shell, SWT.PUSH );
        wOK.setText( BaseMessages.getString( PKG, "System.Button.OK" ) );
        wCancel = new Button( shell, SWT.PUSH );
        wCancel.setText( BaseMessages.getString( PKG, "System.Button.Cancel" ) );

        BaseStepDialog.positionBottomButtons( shell, new Button[] { wOK, wCancel }, margin, tabFolder );

        lsCancel = new Listener() {
            @Override
            public void handleEvent( Event e ) {
                cancel();
            }
        };
        lsOK = new Listener() {
            @Override
            public void handleEvent( Event e ) {
                ok();
            }
        };

        wCancel.addListener( SWT.Selection, lsCancel );
        wOK.addListener( SWT.Selection, lsOK );

        // default listener (for hitting "enter")
        lsDef = new SelectionAdapter() {
            @Override
            public void widgetDefaultSelected( SelectionEvent e ) {
                ok();
            }
        };
        wStepname.addSelectionListener( lsDef );

        privateKeyButton.addSelectionListener( new SelectionAdapter() {
            @Override
            public void widgetSelected( SelectionEvent e ) {
                FileDialog dialog = new FileDialog( shell, SWT.OPEN );
                dialog.setFilterExtensions( new String[] { "*.p12", "*" } );
                dialog.setFilterNames( new String[] { "Private Key files", "All Files" } );
                String filename = dialog.open();
                if ( filename != null ) {
                    try {
                        File keyfile = new File( filename );
                        KeyStore pks = KeyStore.getInstance( "PKCS12" );
                        pks.load( new FileInputStream( keyfile ), GoogleSpreadsheet.SECRET );
                        PrivateKey pk = (PrivateKey) pks.getKey( "privatekey", GoogleSpreadsheet.SECRET );
                        if ( pk != null ) {
                        	privateKeyStore = pks;
                            String clientId = getPrivateKeyClientID(privateKeyStore);
                            privateKeyInfo.setText("Client ID: " + clientId);
                            serviceEmail.setText(GoogleSpreadsheet.getGoogleServiceAccount(clientId));
                            pkcsFilename.setText(filename);
                            meta.setChanged();
                        } else {
                            throw new Exception();
                        }
                    } catch ( Exception err ) {
                        if ( privateKeyStore != null )
                            meta.setChanged();
                        privateKeyStore = null;
                        privateKeyInfo.setText( "Invalid key file" );
                    }
                }
            }
        } );

        testServiceAccountButton.addSelectionListener( new SelectionAdapter() {
            @Override
            public void widgetSelected( SelectionEvent e ) {
                try {
                    testServiceAccountInfo.setText("");
                    
                    if (serviceEmail.getText().startsWith("$") || pkcsFilename.getText().startsWith("$")) {
                		testServiceAccountInfo.setText(BaseMessages.getString(PKG, "Cannot test using variables"));
                		return;
                	}
                    
                    String token = GoogleSpreadsheet.getAccessToken(serviceEmail.getText(), privateKeyStore);
                    if (token == null || token.equals("")) {
                        testServiceAccountInfo.setText("Connection Failed");
                    } else {
                        testServiceAccountInfo.setText("Success!");
                    }
                }
                catch (Exception error) {
                    testServiceAccountInfo.setText("Connection Failed");
                }
            }
        } );

        spreadsheetKeyButton.addSelectionListener( new SelectionAdapter() {
            @Override
            public void widgetSelected( SelectionEvent e ) {
                try {
                    String token = GoogleSpreadsheet.getAccessToken( serviceEmail.getText(), privateKeyStore );
                    SpreadsheetService service = new SpreadsheetService( "PentahoKettleTransformStep-v1" );
                    service.setHeader( "Authorization", "Bearer " + token );

                    SpreadsheetFeed feed = service.getFeed( FeedURLFactory.getDefault().getSpreadsheetsFeedUrl(),
                            SpreadsheetFeed.class );

                    List<SpreadsheetEntry> spreadsheets = feed.getEntries();
                    String[] titles = new String[ spreadsheets.size() ];
                    int selectedSpreadsheet = -1;
                    for ( int i = 0; i < spreadsheets.size(); i++ ) {
                        SpreadsheetEntry entry = spreadsheets.get( i );
                        titles[ i ] = entry.getTitle().getPlainText();
                        if( entry.getKey().equals( spreadsheetKey.getText() )) {
                            selectedSpreadsheet = i;
                        }
                    }

                    EnterSelectionDialog esd = new EnterSelectionDialog( shell, titles, "Spreadsheets",
                            "Select a Spreadsheet." );
                    if ( selectedSpreadsheet > -1 ) {
                        esd.setSelectedNrs( new int[] { selectedSpreadsheet } );
                    }
                    esd.open();
                    if ( esd.getSelectionIndeces().length > 0 ) {
                        selectedSpreadsheet = esd.getSelectionIndeces()[ 0 ];
                        SpreadsheetEntry spreadsheet = spreadsheets.get( selectedSpreadsheet );
                        spreadsheetKey.setText( spreadsheet.getKey() );
                    } else {
                        spreadsheetKey.setText( "" );
                    }

                } catch ( Exception err ) {
                    new ErrorDialog( shell, BaseMessages.getString( PKG, "System.Dialog.Error.Title" ), err
                            .getMessage(), err );
                }
            }
        } );

        worksheetIdButton.addSelectionListener( new SelectionAdapter() {
            @Override
            public void widgetSelected( SelectionEvent e ) {
                try {
                    String token = GoogleSpreadsheet.getAccessToken( serviceEmail.getText(), privateKeyStore );
                    SpreadsheetService service = new SpreadsheetService( "PentahoKettleTransformStep-v1" );
                    service.setHeader( "Authorization", "Bearer " + token );

                    WorksheetFeed feed = service.getFeed(
                            FeedURLFactory.getDefault().getWorksheetFeedUrl( spreadsheetKey.getText(), "private",
                                    "full" ), WorksheetFeed.class );

                    List<WorksheetEntry> worksheets = feed.getEntries();
                    String[] names = new String[ worksheets.size() ];
                    int selectedSheet = -1;
                    for ( int i = 0; i < worksheets.size(); i++ ) {
                        WorksheetEntry sheet = worksheets.get( i );
                        names[ i ] = sheet.getTitle().getPlainText();
                        if ( sheet.getId().endsWith( "/" + worksheetId.getText() ) ) {
                            selectedSheet = i;
                        }
                    }

                    EnterSelectionDialog esd = new EnterSelectionDialog( shell, names, "Worksheets",
                            "Select a Worksheet." );
                    if ( selectedSheet > -1 ) {
                        esd.setSelectedNrs( new int[] { selectedSheet } );
                    }
                    esd.open();

                    if ( esd.getSelectionIndeces().length > 0 ) {
                        selectedSheet = esd.getSelectionIndeces()[ 0 ];
                        WorksheetEntry sheet = worksheets.get( selectedSheet );
                        String id = sheet.getId();
                        worksheetId.setText( id.substring( id.lastIndexOf( "/" ) + 1 ) );
                    } else {
                        worksheetId.setText( "" );
                    }

                } catch ( Exception err ) {
                    new ErrorDialog( shell, BaseMessages.getString( PKG, "System.Dialog.Error.Title" ), err
                            .getMessage(), err );
                }

            }
        } );

        shell.addShellListener( new ShellAdapter() {
            @Override
            public void shellClosed( ShellEvent e ) {
                cancel();
            }
        } );

        tabFolder.setSelection( 0 );
        setSize();
        getData( meta );
        meta.setChanged( changed );

        shell.open();
        while ( !shell.isDisposed() ) {
            if ( !display.readAndDispatch() )
                display.sleep();
        }
        return stepname;
    }

    private void getData( GoogleSpreadsheetOutputMeta meta ) {
        this.wStepname.selectAll();

        this.serviceEmail.setText( meta.getServiceEmail() );
        this.spreadsheetKey.setText( meta.getSpreadsheetKey() );
        this.worksheetId.setText( meta.getWorksheetId() );
        this.pkcsFilename.setText( meta.getPkcsFilename() );

        this.privateKeyStore = meta.getPrivateKeyStore();
        if ( this.privateKeyStore != null ) {
            this.privateKeyInfo.setText( "Client ID: " + getPrivateKeyClientID( this.privateKeyStore ) );
        } else {
            this.privateKeyInfo.setText( "Private key not loaded." );
        }
    }

    private void setData( GoogleSpreadsheetOutputMeta meta ) {
        meta.setServiceEmail( this.serviceEmail.getText() );
        meta.setPrivateKeyStore( this.privateKeyStore );
        meta.setSpreadsheetKey( this.spreadsheetKey.getText() );
        meta.setWorksheetId( this.worksheetId.getText() );
        meta.setPkcsFilename( this.pkcsFilename.getText() );
    }

    private void cancel() {
        stepname = null;
        meta.setChanged( changed );
        dispose();
    }

    private void ok() {
        stepname = wStepname.getText();
        setData( this.meta );
        dispose();
    }

    private String getPrivateKeyClientID( KeyStore keyStore ) {
        try {
            X509Certificate cert = (X509Certificate) keyStore.getCertificate( "privatekey" );
            String name = cert.getIssuerX500Principal().getName( X500Principal.RFC2253 );
            return name.replaceAll( "CN=", "" );
        } catch ( Exception e ) {

        }
        return "";
    }

}
